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
  function vname(s) { return s.veh ? s.veh.name : ""; }
  var COLS = [
    { k: "id", label: "ID", w: 4, min: 3, type: "text", val: function (s) { return s.id || ""; } },
    { k: "gn", label: "GNSS", w: 9, min: 4, type: "text", val: function (s) { return s.gnss || ""; } },
    { k: "nm", label: "SATELLITE", w: 14, min: 5, type: "text", val: vname },
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
    r.appendChild(cell("c-id", s.id || "-"));
    r.appendChild(cell("c-gn", s.gnss));
    r.appendChild(cell("c-nm", vname(s) || "-"));
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
    function pick() {
      sel = { gnssid: s.gnssid, prn: s.prn };
      detail(s, now); drawRows(); sky(last);
      hist(s.gnssid, s.prn, (s.id || s.gnss + " PRN " + s.prn) + (s.veh ? " " + s.veh.name : ""));
    }
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
    var v = s.veh;
    set("gnss-detail-name", (s.id || s.gnss + " PRN " + s.prn) + (v ? " " + v.name : ""));
    var kv = clear($("gnss-detail-kv"));
    [["satellite ID", s.id ? s.id + " (RINEX: system letter and number)" : "-"],
     ["vehicle", v ? v.name + (v.block ? " (" + v.block + ")" : "") : (s.gnss === "SBAS" ? "- (SBAS is not in the IGS metadata)" : "- (not in the IGS metadata)")],
     ["NORAD catalog #", v && v.norad ? String(v.norad) : null],
     ["COSPAR ID", v ? v.cospar : null],
     ["SVN", v ? v.svn : null],
     ["launched", v && v.launched ? v.launched : null],
     ["orbital plane / slot", v && v.plane ? v.plane + " / " + v.slot : null],
     ["constellation", s.gnss + " (gnssid " + s.gnssid + ")"],
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
  function closeDetail() { $("gnss-detail").hidden = true; sel = null; drawRows(); sky(last); }

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
    // The trails (sloth.db's gnss_sightings, /api/gnss/tracks): each
    // satellite's path over the window, fading toward its oldest point,
    // the selected one bold. A point under the horizon is drawn on it.
    function P(el, az) {
      var r = R * (90 - Math.max(0, el)) / 90, a = (az - 90) * Math.PI / 180;
      return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
    }
    var tcol = cssVar("--tui-dim", "#888");
    (trails && trails.tracks || []).forEach(function (t) {
      var pts = t.pts || [];
      if (pts.length < 2) return;
      var picked = sel && sel.gnssid === t.gnssid && sel.prn === t.prn;
      g.strokeStyle = picked ? cssVar("--signal", tcol) : tcol;
      g.lineWidth = picked ? 2 : 1;
      for (var i = 1; i < pts.length; i++) {
        // A gap over two buckets is the satellite setting and rising
        // again: no line across the sky.
        if (pts[i][0] - pts[i - 1][0] > 2 * trails.bucket_s + 60) continue;
        var a0 = P(pts[i - 1][1], pts[i - 1][2]), a1 = P(pts[i][1], pts[i][2]);
        g.globalAlpha = 0.15 + 0.6 * i / pts.length;
        g.beginPath(); g.moveTo(a0[0], a0[1]); g.lineTo(a1[0], a1[1]); g.stroke();
      }
      g.globalAlpha = 1;
    });
    g.lineWidth = 1;
    (j.sats || []).forEach(function (s) {
      if (!num(s.el) || !num(s.az)) return;
      var r = R * (90 - s.el) / 90, a = (s.az - 90) * Math.PI / 180;
      var x = cx + r * Math.cos(a), y = cy + r * Math.sin(a);
      var f = num(s.cn0) ? s.cn0 / SPAN_DBHZ : 0;
      g.fillStyle = num(s.cn0) ? heatColor(f) : cssVar("--tui-dim", "#888");
      g.beginPath(); g.arc(x, y, s.used ? 6 : 4, 0, Math.PI * 2); g.fill();
      if (s.health === 2) { g.strokeStyle = cssVar("--heat-3", "#f00"); g.beginPath(); g.arc(x, y, 8, 0, Math.PI * 2); g.stroke(); }
      g.fillStyle = cssVar("--ink", "currentColor");
      g.fillText(s.id || (s.gnss.charAt(0) + (num(s.svid) ? s.svid : s.prn)), x, y - 9);
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

  // ── history: sloth.db's gnss_sightings (web_rfhist.h) ────────────
  // The satellites seen over a window, and one satellite's C/N0 and
  // elevation over it. Read once a minute while the view shows, not at
  // POLL_MS: sloth writes a sighting per banded change, not per second.
  var SEEN_MS = 60000, seenAt = 0, seenGen = 0, histSel = null, histGen = 0;
  function when(ts) {
    if (!num(ts) || ts <= 0) return "-";
    var d = new Date(ts * 1000), p = function (n) { return (n < 10 ? "0" : "") + n; };
    return (d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
  }
  var ST = null, seenRows = [], seenLast = null;
  var SEEN_COLS = [
    { k: "id", label: "ID", w: 4, min: 3, type: "text", val: function (g) { return g.id || ""; } },
    { k: "gn", label: "GNSS", w: 9, min: 4, type: "text", val: function (g) { return g.gnss; } },
    { k: "nm", label: "SATELLITE", w: 14, min: 5, type: "text", val: vname },
    { k: "nr", label: "NORAD", w: 6, min: 4, num: true, type: "num", val: function (g) { return g.veh ? g.veh.norad : null; } },
    { k: "pr", label: "PRN", w: 5, min: 3, num: true, type: "num", val: val("prn") },
    { k: "sv", label: "SV", w: 4, min: 2, num: true, type: "num", val: val("svid") },
    { k: "fs", label: "FIRST", w: 11, min: 5, type: "time", val: val("first_seen") },
    { k: "ls", label: "LAST", w: 11, min: 5, type: "time", val: val("last_seen") },
    { k: "rc", label: "RECORDS", w: 8, min: 4, num: true, type: "num", val: val("records") },
    { k: "us", label: "USED %", w: 7, min: 4, num: true, type: "num", val: val("used_pct") },
    { k: "cx", label: "C/N0 MAX", w: 8, min: 4, num: true, type: "num", val: val("cn0_max") },
    { k: "cm", label: "C/N0 MEAN", w: 9, min: 4, num: true, type: "num", val: val("cn0_mean") },
    { k: "el", label: "EL MAX", w: 7, min: 3, num: true, type: "num", val: val("el_max") }
  ];
  function seenTable() {
    if (ST || !window.SlothTables || !$("gnss-seen-box")) return ST;
    ST = window.SlothTables.make({ id: "gnss-seen", label: "satellites seen", box: $("gnss-seen-box"),
      head: $("gnss-seen-thead"), reset: $("gnss-seen-tools"), redraw: drawSeen, cols: SEEN_COLS });
    return ST;
  }
  function drawSeen() {
    var j = seenLast;
    if (!j) return;
    var t = seenTable();
    var ordered = t ? t.sort(seenRows, true) : seenRows.slice();
    var body = clear($("gnss-seen-rows"));
    set("gnss-seen-count", j.have === false ? "sloth.db has no gnss_sightings yet" :
      seenRows.length + (j.more ? "+" : "") + " in " + (j.days === 1 ? "24 h" : j.days + " days"));
    ordered.forEach(function (g) {
      var on = histSel && histSel.gnssid === g.gnssid && histSel.prn === g.prn;
      var r = el("div", "histrow dt-row d-normal" + (on ? " on" : ""));
      r.appendChild(cell("c-id", g.id || "-"));
      r.appendChild(cell("c-gn", g.gnss));
      r.appendChild(cell("c-nm", vname(g) || "-"));
      r.appendChild(cell("c-nr n", g.veh ? g.veh.norad : "-"));
      r.appendChild(cell("c-pr n", g.prn));
      r.appendChild(cell("c-sv n", num(g.svid) ? g.svid : "-"));
      r.appendChild(cell("c-fs d-dim", when(g.first_seen)));
      r.appendChild(cell("c-ls", when(g.last_seen)));
      r.appendChild(cell("c-rc n", g.records));
      r.appendChild(cell("c-us n", fx(g.used_pct, 0)));
      r.appendChild(cell("c-cx n " + (num(g.cn0_max) ? heatClass(g.cn0_max / SPAN_DBHZ) : "d-dim"), fx(g.cn0_max, 1)));
      r.appendChild(cell("c-cm n " + (num(g.cn0_mean) ? heatClass(g.cn0_mean / SPAN_DBHZ) : "d-dim"), fx(g.cn0_mean, 1)));
      r.appendChild(cell("c-el n", num(g.el_max) ? g.el_max : "-"));
      r.tabIndex = 0;
      function pick() { hist(g.gnssid, g.prn, (g.id || g.gnss + " PRN " + g.prn) + (g.veh ? " " + g.veh.name : "")); }
      r.addEventListener("click", pick);
      r.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
      body.appendChild(r);
    });
  }
  function seenDays() { var s = $("gnss-seen-days"); return s ? s.value : "1"; }
  function loadSeen() {
    var my = ++seenGen;
    seenAt = Date.now();
    getJSON("/api/gnss/seen?days=" + encodeURIComponent(seenDays())).then(function (j) {
      if (my !== seenGen) return;
      seenLast = j;
      seenRows = (j.sats || []).slice();
      drawSeen();
    }).catch(function (e) {
      if (my !== seenGen) return;
      set("gnss-seen-count", "history unavailable: " + (e && e.message ? e.message : "error") + " (needs --sloth-db)");
    });
  }
  function hist(gnssid, prn, label) {
    histSel = { gnssid: gnssid, prn: prn, label: label };
    var my = ++histGen;
    $("gnss-hist").hidden = false;
    set("gnss-hist-note", "loading");
    drawSeen();
    getJSON("/api/gnss/sat?gnssid=" + gnssid + "&prn=" + prn + "&days=" + encodeURIComponent(seenDays())).then(function (j) {
      if (my !== histGen) return;
      set("gnss-hist-name", (label || j.gnss + " PRN " + j.prn) + " over " + (j.days === 1 ? "24 h" : j.days + " days"));
      histPlot(j.points || []);
    }).catch(function (e) {
      if (my !== histGen) return;
      set("gnss-hist-note", "history unavailable: " + (e && e.message ? e.message : "error"));
    });
  }
  // Two lanes over one time axis: C/N0 (0..50 dB-Hz) heat-graded, a
  // larger dot when the record was in the solution; elevation (0..90).
  function histPlot(pts) {
    var c = $("gnss-hist-plot");
    if (!c) return;
    var dpr = window.devicePixelRatio || 1, W = Math.max(200, c.clientWidth || 400), H = 160;
    c.width = W * dpr; c.height = H * dpr;
    var g = c.getContext("2d");
    if (!g) return;
    g.scale(dpr, dpr);
    g.clearRect(0, 0, W, H);
    if (!pts.length) { set("gnss-hist-note", "no records in the window"); return; }
    var t0 = pts[0][0], t1 = pts[pts.length - 1][0], span = Math.max(1, t1 - t0), lh = H / 2;
    var dim = cssVar("--tui-dim", "#888");
    g.strokeStyle = dim; g.fillStyle = dim; g.lineWidth = 1; g.font = "11px monospace";
    g.beginPath(); g.moveTo(0, lh - 0.5); g.lineTo(W, lh - 0.5); g.stroke();
    g.fillText("C/N0", 4, 12); g.fillText("elevation", 4, lh + 12);
    function X(ts) { return pts.length === 1 ? W - 4 : 2 + (ts - t0) / span * (W - 6); }
    var px = null, py = null;
    pts.forEach(function (p) {
      var x = X(p[0]);
      if (num(p[3])) {
        var f = Math.min(1, p[3] / SPAN_DBHZ);
        g.fillStyle = heatColor(f);
        var r = p[4] ? 2.5 : 1.5;
        g.fillRect(x - r, lh - 3 - f * (lh - 16) - r, 2 * r, 2 * r);
      }
      if (num(p[1])) {
        var y = H - 3 - Math.max(0, Math.min(90, p[1])) / 90 * (lh - 16);
        g.strokeStyle = cssVar("--ink", "currentColor");
        if (px !== null) { g.beginPath(); g.moveTo(px, py); g.lineTo(x, y); g.stroke(); }
        px = x; py = y;
      } else { px = null; }
    });
    var used = pts.filter(function (p) { return p[4]; }).length;
    set("gnss-hist-note", pts.length + " records from " + when(t0) + " to " + when(t1) +
      ", " + used + " in the solution; larger dots were used. C/N0 over 0..50 dB-Hz, elevation 0..90 deg.");
  }

  // The sky trails, once a minute: a satellite moves about half a
  // degree a minute across the sky, and sloth records it per band.
  var trails = null, trailAt = 0, trailGen = 0;
  function trailHours() { var s = $("gnss-trail-hours"); return s ? s.value : "6"; }
  function loadTrails() {
    var my = ++trailGen;
    trailAt = Date.now();
    getJSON("/api/gnss/tracks?hours=" + encodeURIComponent(trailHours())).then(function (j) {
      if (my !== trailGen) return;
      trails = j;
      set("gnss-trail-note", j.have === false ? "no sloth.db history yet" :
        j.total + " trails over " + j.hours + " h" + (j.cut ? " (cut at the point cap)" : ""));
      if (last) sky(last);
    }).catch(function () {
      if (my !== trailGen) return;
      trails = null;
      set("gnss-trail-note", "trails need --sloth-db");
    });
  }
  // Another module's pick (radar.js): the satellite selected as a row's
  // click would select it; one not listed yet is applied by the next load().
  function select(gnssid, prn) {
    if (!num(gnssid) || !num(prn)) return;
    sel = { gnssid: gnssid, prn: prn };
    var cur = rows.filter(function (s) { return s.gnssid === gnssid && s.prn === prn; })[0];
    if (cur) {
      detail(cur, num(last && last.now) ? last.now : Math.floor(Date.now() / 1000));
      hist(gnssid, prn, (cur.id || cur.gnss + " PRN " + cur.prn) + (cur.veh ? " " + cur.veh.name : ""));
    }
    drawRows();
    if (last) sky(last);
  }
  function show() {
    if (!$("v-gnss")) return;
    load();
    if (Date.now() - seenAt > SEEN_MS) loadSeen();
    if (Date.now() - trailAt > SEEN_MS) loadTrails();
    if (!timer) timer = setInterval(function () {
      if (!visible()) return;
      load();
      if (Date.now() - seenAt > SEEN_MS) loadSeen();
      if (Date.now() - trailAt > SEEN_MS) loadTrails();
    }, POLL_MS);
  }
  var trailSel = $("gnss-trail-hours");
  if (trailSel) trailSel.addEventListener("change", loadTrails);
  var daysSel = $("gnss-seen-days");
  if (daysSel) daysSel.addEventListener("change", function () {
    loadSeen();
    if (histSel) hist(histSel.gnssid, histSel.prn, histSel.label);
  });
  var histClose = $("gnss-hist-close");
  if (histClose) histClose.addEventListener("click", function () { $("gnss-hist").hidden = true; histSel = null; drawSeen(); });

  var closeBtn = $("gnss-detail-close");
  if (closeBtn) closeBtn.addEventListener("click", closeDetail);

  window.SlothGnss = { show: show, select: select };
})();
