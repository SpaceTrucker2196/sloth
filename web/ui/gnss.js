// slothweb: the GNSS panel (2026-11-02, web_gnss.h, docs/wiki/gnss.md).
// window.SlothGnss, one hook app.js calls when the view shows:
//   SlothGnss.show()   loads /api/gnss into the gnss-* containers and
//                      keeps it current while the view is visible
// Same-origin relative paths only, every value shown with textContent,
// no tiles and nothing fetched from anywhere else. The receiver is the
// host's own, so the panel is every scope's and the page says so.
// Colours are the palette's: the C/N0 heat ramp uses the TUI's
// thresholds (app.js heatClass: 0.15 / 0.40 / 0.70 of 50 dB-Hz). The
// satellites table is app.js's DataTable (window.SlothTables.make), as
// every table on the page is; the fix strip walks /api/gnss/fixes
// with since= so it reaches the newest record once the ring is full.
(function () {
  "use strict";
  var POLL_MS = 5000, SPAN_DBHZ = 50;
  var timer = 0, gen = 0, last = null, sel = null;

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
  function heatColor(f) {
    return cssVar("--heat-" + (f < 0.15 ? 0 : f < 0.40 ? 1 : f < 0.70 ? 2 : 3), "currentColor");
  }
  function visible() { var v = $("v-gnss"); return v && !v.hidden; }
  function age(ts, now) {
    if (!num(ts) || ts <= 0) return "-";
    var a = Math.max(0, now - ts);
    return a < 60 ? a + "s" : a < 3600 ? Math.floor(a / 60) + "m" : Math.floor(a / 3600) + "h";
  }
  var MODE = { 0: "unknown", 1: "no fix", 2: "2D", 3: "3D" };
  var STATUS = { 1: "normal", 2: "DGPS", 3: "RTK fix", 4: "RTK float", 5: "DR", 6: "GNSS+DR",
                 7: "time-surveyed", 8: "simulated", 9: "P(Y)" };
  var HEALTH = { 1: "ok", 2: "BAD" };

  function getJSON(path) {
    return fetch(path, { credentials: "same-origin", cache: "no-store" }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
  }

  // ── the header: the TUI's two lines ──────────────────────────────
  function header(j) {
    var now = num(j.now) ? j.now : Math.floor(Date.now() / 1000);
    var f = j.fix, k = j.sky, s = j.sensor;
    var h = clear($("gnss-head"));
    if (!s && !f && !k) {
      h.appendChild(el("span", "", "GNSS: no receiver"));
      var e = $("gnss-empty");
      e.hidden = false;
      e.textContent = "no gnss records yet: sloth needs --gps gpsd:// or --gps /dev/ttyXXX (docs/wiki/gnss.md); --location alone is a setting, not a receiver";
      $("gnss-head2").textContent = "";
      return;
    }
    $("gnss-empty").hidden = true;
    h.appendChild(el("span", "", "GNSS: fix "));
    var mode = f ? MODE[f.mode] || "unknown" : "none";
    h.appendChild(el("b", f && f.mode >= 2 ? "" : "h2", mode));
    var usat = k && num(k.usat) ? k.usat : (s ? s.sats_used : 0);
    var nsat = k && num(k.nsat) ? k.nsat : (s ? s.sats_in_view : 0);
    h.appendChild(el("span", "", "  sats "));
    h.appendChild(el("b", "", usat + "/" + nsat));
    var hd = k && num(k.hdop) ? k.hdop : (f && num(f.hdop) ? f.hdop : null);
    var pd = k && num(k.pdop) ? k.pdop : (f && num(f.pdop) ? f.pdop : null);
    h.appendChild(el("span", "", "  HDOP "));
    h.appendChild(el("span", num(hd) ? (hd < 2 ? "h0" : hd < 5 ? "h2" : "h3") : "d-dim", fx(hd, 1)));
    h.appendChild(el("span", "", " PDOP "));
    h.appendChild(el("span", num(pd) ? (pd < 2 ? "h0" : pd < 5 ? "h2" : "h3") : "d-dim", fx(pd, 1)));
    if (f && num(f.eph)) h.appendChild(el("span", "", "  acc ±" + Math.round(f.eph) + " m"));
    if (f && num(f.speed_mps)) h.appendChild(el("span", "", "  speed " + f.speed_mps.toFixed(1) + " m/s"));
    h.appendChild(el("span", "", "  clock off "));
    var off = f && num(f.time_off_ms) ? f.time_off_ms : (s && num(s.time_off_ms) ? s.time_off_ms : null);
    if (num(off)) {
      var a = Math.abs(off);
      h.appendChild(el("span", a < 500 ? "h0" : a < 2000 ? "h2" : "h3", (off >= 0 ? "+" : "") + off + " ms"));
    } else {
      h.appendChild(el("span", "d-dim", "-"));
    }
    h.appendChild(el("span", "d-dim", "  src " + (j.src || "-") + "  age " + age(k ? k.ts : (f ? f.ts : 0), now)));
    var h2 = clear($("gnss-head2"));
    var parts = ["status " + (f && num(f.status) ? STATUS[f.status] || "unknown" : "-")];
    if (f && num(f.leap)) parts.push("leap " + f.leap);
    var jam = f && num(f.jam) ? f.jam : (s && num(s.jam) ? s.jam : null);
    h2.appendChild(el("span", "", parts.join("  ") + "  jam "));
    if (num(jam)) h2.appendChild(el("span", jam === 0 ? "" : jam < 64 ? "h1" : jam < 128 ? "h2" : "h3", String(jam)));
    else h2.appendChild(el("span", "d-dim", "-"));
    h2.appendChild(el("span", "", "  C/N0 mean " + (k ? fx(k.cn0_mean, 1) : "-") + " max " + (k ? fx(k.cn0_max, 1) : "-") +
      (k && num(k.cn0_sd) ? " sd " + fx(k.cn0_sd, 1) : "") +
      (s ? "  sensor " + s.state : "") +
      "  records " + j.records + (j.evictions ? "  evicted " + j.evictions : "") +
      (j.rejected ? "  rejected " + j.rejected : "")));
  }

  // ── the table ────────────────────────────────────────────────────
  // One of app.js's DataTable (window.SlothTables.make, the owner's
  // 2026-10-26 ruling: every table on the page is one implementation):
  // kept column widths and sort, aria-sort on the header buttons,
  // drag / keyboard / double-click sizing, "reset columns". Made on
  // first show: app.js's main() has run by then. With no sort set the
  // rows stay in the server's order, which is the TUI's (C/N0,
  // strongest first, untracked last).
  var T = null, rows = [];
  function val(k) { return function (s) { return num(s[k]) ? s[k] : null; }; }
  var COLS = [
    { k: "gn", label: "GNSS", w: 9, min: 4, type: "text", val: function (s) { return s.gnss || ""; } },
    { k: "sv", label: "SV", w: 4, min: 2, num: true, type: "num", val: val("svid") },
    { k: "pr", label: "PRN", w: 5, min: 3, num: true, type: "num", val: val("prn") },
    { k: "el", label: "EL", w: 4, min: 2, num: true, type: "num", val: val("el") },
    { k: "az", label: "AZ", w: 4, min: 2, num: true, type: "num", val: val("az") },
    { k: "cn", label: "C/N0", w: 6, min: 4, num: true, type: "num", val: val("cn0") },
    { k: "us", label: "USED", w: 5, min: 3, type: "text", val: function (s) { return s.used ? "yes" : "-"; } },
    { k: "hl", label: "HLTH", w: 5, min: 3, type: "text", val: function (s) { return num(s.health) ? HEALTH[s.health] || "?" : "?"; } },
    { k: "sg", label: "SIGNAL", w: 12, min: 6, type: "num", val: val("cn0") },
    { k: "tr", label: "TRAIL", w: 13, min: 6, type: "none" },
    { k: "ag", label: "AGE", w: 5, min: 3, type: "time", val: val("ts") }
  ];
  function table() {
    if (T || !window.SlothTables || !$("gnss-box")) return T;
    T = window.SlothTables.make({ id: "gnss", label: "satellites in view", box: $("gnss-box"),
      head: $("gnss-thead"), reset: $("gnss-tools"), redraw: drawRows, cols: COLS });
    return T;
  }
  function cell(cls, text) { var c = el("span", cls); if (text !== undefined) c.textContent = String(text); return c; }
  function trail(c, pts) {
    var dpr = window.devicePixelRatio || 1, W = 96, H = 14;
    c.width = W * dpr; c.height = H * dpr;
    var g = c.getContext("2d");
    if (!g) return;
    g.scale(dpr, dpr);
    g.clearRect(0, 0, W, H);
    if (!pts || pts.length < 1) return;
    var t0 = pts[0][0], t1 = pts[pts.length - 1][0], span = Math.max(1, t1 - t0);
    g.lineWidth = 1.5;
    var px = 0, py = 0;
    for (var i = 0; i < pts.length; i++) {
      var x = pts.length === 1 ? W - 2 : 1 + (pts[i][0] - t0) / span * (W - 3);
      var y = H - 1 - Math.min(1, pts[i][1] / SPAN_DBHZ) * (H - 2);
      g.strokeStyle = heatColor(pts[i][1] / SPAN_DBHZ);
      if (i) { g.beginPath(); g.moveTo(px, py); g.lineTo(x, y); g.stroke(); }
      g.fillStyle = g.strokeStyle;
      g.fillRect(x - 1, y - 1, 2, 2);
      px = x; py = y;
    }
  }
  // A row under the columns: bright when in the solution, dim when
  // unhealthy, the TUI's; the signal cell heat-graded over 50 dB-Hz.
  function row(s, now, j) {
    var on = sel && sel.gnssid === s.gnssid && sel.prn === s.prn;
    var cls = s.health === 2 ? "d-dim" : s.used ? "d-bright" : "d-normal";
    var r = el("div", "gnssrow dt-row " + cls + (on ? " on" : ""));
    r.appendChild(cell("c-gn", s.gnss));
    r.appendChild(cell("c-sv n", num(s.svid) ? s.svid : "-"));
    r.appendChild(cell("c-pr n", s.prn));
    r.appendChild(cell("c-el n", num(s.el) ? s.el : "-"));
    r.appendChild(cell("c-az n", num(s.az) ? s.az : "-"));
    r.appendChild(cell("c-cn n " + (num(s.cn0) ? heatClass(s.cn0 / SPAN_DBHZ) : "d-dim"), fx(s.cn0, 1)));
    r.appendChild(cell("c-us", s.used ? "yes" : "-"));
    r.appendChild(cell("c-hl", num(s.health) ? HEALTH[s.health] || "?" : "?"));
    var sig = cell("c-sg " + (num(s.cn0) ? heatClass(s.cn0 / SPAN_DBHZ) : ""));
    var bar = el("span", "gnss-bar");
    bar.style.width = (num(s.cn0) ? Math.round(Math.min(1, s.cn0 / SPAN_DBHZ) * 100) : 0) + "%";
    sig.appendChild(bar);
    r.appendChild(sig);
    var tc = cell("c-tr");
    var c = el("canvas", "trail");
    c.title = "C/N0 over the row's last records";
    tc.appendChild(c);
    r.appendChild(tc);
    r.appendChild(cell("c-ag d-dim", age(s.ts, now)));
    r.tabIndex = 0;
    function pick() { sel = { gnssid: s.gnssid, prn: s.prn }; detail(s, now); drawRows(); }
    r.addEventListener("click", pick);
    r.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
    r._trail = [c, s.points];
    void j;
    return r;
  }
  function drawRows() {
    if (!last) return;
    var j = last, now = num(j.now) ? j.now : Math.floor(Date.now() / 1000);
    var t = table();
    var ordered = t ? t.sort(rows, true) : rows.slice();
    var body = clear($("gnss-rows"));
    set("gnss-count", rows.length + (j.sky && j.sky.overflow ? " (+" + j.sky.overflow + " more than sloth's table holds)" : ""));
    var drawn = [];
    ordered.forEach(function (s) { var r = row(s, now, j); body.appendChild(r); drawn.push(r); });
    drawn.forEach(function (r) { trail(r._trail[0], r._trail[1]); });
  }
  function tableLoad(j) {
    rows = (j.sats || []).slice();
    drawRows();
  }

  // ── the detail: the TUI's kv rows ────────────────────────────────
  function detail(s, now) {
    var box = $("gnss-detail");
    box.hidden = false;
    set("gnss-detail-name", s.gnss + " PRN " + s.prn);
    var kv = clear($("gnss-detail-kv"));
    [["constellation", s.gnss + " (gnssid " + s.gnssid + ")"],
     ["svid", num(s.svid) ? String(s.svid) : "-"],
     ["PRN", String(s.prn)],
     ["signal id", num(s.sigid) ? String(s.sigid) : null],
     ["elevation", num(s.el) ? s.el + " deg" : null],
     ["azimuth", num(s.az) ? s.az + " deg true" : null],
     ["C/N0", num(s.cn0) ? s.cn0.toFixed(1) + " dB-Hz" : "- (not tracked)"],
     ["used in solution", s.used ? "yes" : "no"],
     ["health", num(s.health) ? HEALTH[s.health] || "unknown" : "unknown"],
     ["records", String(s.records)],
     ["first record", age(s.first_ts, now) + " ago"],
     ["last record", age(s.ts, now) + " ago (pass " + s.sky_ts + ")"]
    ].forEach(function (p) {
      if (p[1] === null) return;
      kv.appendChild(el("dt", "", p[0]));
      kv.appendChild(el("dd", "", p[1]));
    });
  }
  function closeDetail() { $("gnss-detail").hidden = true; sel = null; drawRows(); }

  // ── the sky: a polar plot, north up, elevation inward ────────────
  function sky(j) {
    var c = $("gnss-sky");
    if (!c) return;
    var dpr = window.devicePixelRatio || 1, S = 320;
    c.width = S * dpr; c.height = S * dpr;
    var g = c.getContext("2d");
    if (!g) return;
    g.scale(dpr, dpr);
    g.clearRect(0, 0, S, S);
    var cx = S / 2, cy = S / 2, R = S / 2 - 14;
    g.strokeStyle = cssVar("--tui-dim", "#888");
    g.fillStyle = g.strokeStyle;
    g.lineWidth = 1;
    g.font = "11px monospace";
    g.textAlign = "center";
    [90, 60, 30, 0].forEach(function (elv) {
      var r = R * (90 - elv) / 90;
      g.beginPath(); g.arc(cx, cy, Math.max(1, r), 0, Math.PI * 2); g.stroke();
      if (elv) g.fillText(String(elv), cx + 10, cy - r + 11);
    });
    g.beginPath(); g.moveTo(cx, cy - R); g.lineTo(cx, cy + R); g.moveTo(cx - R, cy); g.lineTo(cx + R, cy); g.stroke();
    g.fillText("N", cx, 10); g.fillText("S", cx, S - 2); g.fillText("E", S - 6, cy + 4); g.fillText("W", 6, cy + 4);
    (j.sats || []).forEach(function (s) {
      if (!num(s.el) || !num(s.az)) return;
      var r = R * (90 - s.el) / 90, a = (s.az - 90) * Math.PI / 180;
      var x = cx + r * Math.cos(a), y = cy + r * Math.sin(a);
      var f = num(s.cn0) ? s.cn0 / SPAN_DBHZ : 0;
      g.fillStyle = num(s.cn0) ? heatColor(f) : cssVar("--tui-dim", "#888");
      g.beginPath(); g.arc(x, y, s.used ? 6 : 4, 0, Math.PI * 2); g.fill();
      if (s.health === 2) { g.strokeStyle = cssVar("--heat-3", "#f00"); g.beginPath(); g.arc(x, y, 8, 0, Math.PI * 2); g.stroke(); }
      g.fillStyle = cssVar("--ink", "currentColor");
      g.fillText(s.gnss.charAt(0) + (num(s.svid) ? s.svid : s.prn), x, y - 9);
    });
  }

  // ── the fix history: four strips over the kept gnss_fix records ──
  function fixstrip(rows, now) {
    var c = $("gnss-fixstrip");
    if (!c) return;
    var dpr = window.devicePixelRatio || 1, W = Math.max(200, c.clientWidth || 400), H = 120;
    c.width = W * dpr; c.height = H * dpr;
    var g = c.getContext("2d");
    if (!g) return;
    g.scale(dpr, dpr);
    g.clearRect(0, 0, W, H);
    set("gnss-fix-legend", "top to bottom: fix mode (0..3), satellites used, HDOP (0..10), clock offset (±2 s); one point per gnss_fix record, oldest left");
    if (!rows || !rows.length) { set("gnss-fix-note", "no gnss_fix records yet"); return; }
    set("gnss-fix-note", rows.length + " records, " + age(rows[0].ts, now) + " to " + age(rows[rows.length - 1].ts, now) + " ago");
    var t0 = rows[0].ts, t1 = rows[rows.length - 1].ts, span = Math.max(1, t1 - t0);
    var lanes = [
      { key: "mode", lo: 0, hi: 3 }, { key: "usat", lo: 0, hi: 16 },
      { key: "hdop", lo: 0, hi: 10 }, { key: "time_off_ms", lo: -2000, hi: 2000 }
    ];
    var lh = H / lanes.length;
    g.strokeStyle = cssVar("--tui-dim", "#888");
    g.lineWidth = 1;
    lanes.forEach(function (ln, i) {
      var y0 = i * lh;
      g.beginPath(); g.moveTo(0, y0 + lh - 0.5); g.lineTo(W, y0 + lh - 0.5); g.stroke();
      var px = null, py = null;
      rows.forEach(function (r) {
        var v = r[ln.key];
        if (!num(v)) { px = null; return; }
        var x = rows.length === 1 ? W - 2 : (r.ts - t0) / span * (W - 2) + 1;
        var f = Math.max(0, Math.min(1, (v - ln.lo) / (ln.hi - ln.lo)));
        var y = y0 + lh - 2 - f * (lh - 4);
        var heat = ln.key === "mode" ? 1 - f : ln.key === "usat" ? 1 - f : f;
        g.strokeStyle = heatColor(ln.key === "time_off_ms" ? Math.min(1, Math.abs(v) / 2000) : heat);
        g.fillStyle = g.strokeStyle;
        if (px !== null) { g.beginPath(); g.moveTo(px, py); g.lineTo(x, y); g.stroke(); }
        g.fillRect(x - 1, y - 1, 2, 2);
        px = x; py = y;
      });
    });
  }

  // The fix ring, walked: /api/gnss/fixes answers oldest first, at most
  // FIX_PAGE rows after since=, so one request would show the oldest
  // 128 of 512 for ever once the ring had filled. From since=0, then
  // from the last row's ts while a page comes back full, at most
  // FIX_PAGES pages (the ring is 512 = 4 pages; the margin is for rows
  // arriving under the walk). Two fixes in one second share a ts and
  // the second is skipped by the next page: accepted, it is a strip.
  var FIX_PAGE = 128, FIX_PAGES = 8;
  function fixes(since, acc, pages) {
    return getJSON("/api/gnss/fixes?since=" + since).then(function (f) {
      var got = f.rows || [];
      acc = acc.concat(got);
      var lastTs = got.length ? got[got.length - 1].ts : since;
      if (got.length >= FIX_PAGE && pages + 1 < FIX_PAGES && num(lastTs) && lastTs > since)
        return fixes(lastTs, acc, pages + 1);
      return { rows: acc, now: f.now };
    });
  }
  function load() {
    var my = ++gen;
    getJSON("/api/gnss").then(function (j) {
      if (my !== gen || !visible()) return;
      last = j;
      header(j);
      tableLoad(j);
      sky(j);
      if (sel) {
        var cur = (j.sats || []).filter(function (s) { return s.gnssid === sel.gnssid && s.prn === sel.prn; })[0];
        if (cur) detail(cur, num(j.now) ? j.now : Math.floor(Date.now() / 1000));
      }
      return fixes(0, [], 0).then(function (f) {
        if (my !== gen || !visible()) return;
        fixstrip(f.rows || [], num(f.now) ? f.now : Math.floor(Date.now() / 1000));
      });
    }).catch(function (e) {
      if (my !== gen) return;
      set("gnss-head", "GNSS: " + (e && e.message ? e.message : "error"));
    });
  }

  function show() {
    if (!$("v-gnss")) return;
    load();
    if (!timer) timer = setInterval(function () { if (visible()) load(); }, POLL_MS);
  }

  var closeBtn = $("gnss-detail-close");
  if (closeBtn) closeBtn.addEventListener("click", closeDetail);

  window.SlothGnss = { show: show };
})();
