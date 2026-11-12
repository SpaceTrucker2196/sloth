// slothweb: the sensor's host status on the Sensor health view
// (2026-11-11, web_sysstat.h, docs/wiki/jsonl-schema.md "Host status
// and the source inventory"). window.SlothSysHealth, two hooks app.js
// calls:
//   SlothSysHealth.init(h)   once, main()'s helpers lent
//   SlothSysHealth.show()    when the health view shows: loads /api/sys
//                            into the sy-* containers, draws the trends,
//                            and keeps both current while it is visible
// Three panels: every source and attached receiver as two tables (each
// app.js's DataTable), the host's status as tiles, and the trends: G1
// over its hour-of-week band for each figure, G5 as a source's up/down
// strip (glyph.g5(), called here; the glyph itself is not changed).
//
// sloth's own state, so every scope's: /api/sys takes no scope, and the
// series are read as Hybrid's whatever the page's scope is (they are
// tagged to no radio), which is why this module fetches them itself
// and does not go through the page's scoped getJSON.
//
// Every string shown is the sensor's, and behind it a device's (a USB
// product string is whatever the plugged-in thing says): textContent
// only, no markup sink, no attribute written from a value.
(function () {
  "use strict";
  var H = null;
  var POLL_MS = 15000, TREND_MS = 300000, CELLS = 96, MIN_N = 12;
  var WINS = { "3600": "1 h", "21600": "6 h", "86400": "24 h", "604800": "7 d", "2592000": "30 d" };
  var S = { gen: 0, tgen: 0, timer: 0, ttimer: 0, last: null, rows: [], hw: [],
            scale: {}, scaleOf: "", trendAt: 0 };
  var ST = null, HT = null;

  function $(id) { return document.getElementById(id); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); return n; }
  function set(id, text) { var e = $(id); if (e) e.textContent = String(text); }
  function visible() { var v = $("v-health"); return v && !v.hidden; }
  // Degrees C, as sloth reads them, to the F the page shows.
  function cToF(c) { return c * 9 / 5 + 32; }
  function fx(v, dp) { return num(v) ? v.toFixed(dp) : null; }
  var ABSENT = "not reported by this host";

  // Unscoped on purpose (the header says why). Same-origin, relative.
  function getJSON(path) {
    return fetch(path, { credentials: "same-origin", cache: "no-store" }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) throw new Error(j && typeof j.error === "string" ? j.error : String(r.status));
        return j;
      });
    });
  }
  function seriesOf(m, key, tier, from, to) {
    var all = [], pages = 0, meta = null;
    function page(t) {
      var p = "/api/series?metric=" + encodeURIComponent(m) + "&tier=" + tier + "&from=" + from + "&to=" + t;
      if (key !== "") p += "&key=" + encodeURIComponent(key);
      return getJSON(p).then(function (j) {
        meta = j;
        all = (j.points || []).concat(all);
        pages++;
        if (j.more && num(j.next_to) && j.next_to > from && pages < 12) return page(j.next_to);
        return { points: all, kind: meta.kind, unit: meta.unit, step: meta.step };
      });
    }
    return page(to);
  }
  function baselineOf(m, key) {
    var p = "/api/baseline?metric=" + encodeURIComponent(m);
    if (key !== "") p += "&key=" + encodeURIComponent(key);
    return getJSON(p).catch(function () { return null; });
  }

  // \u2500\u2500 the pure half: what a series says in words \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  // web/tests/test_sysstat.c ports these three line for line and pins
  // their text out of the served page, as test_glyph.c does glyph.js.

  function median(a) {
    if (!a.length) return NaN;
    var s = a.slice().sort(function (x, y) { return x - y; }), m = s.length >> 1;
    return s.length & 1 ? s[m] : (s[m - 1] + s[m]) / 2;
  }

  // The trend over the window, by a stated rule: the median of the last
  // third of the samples against the median of the first third, called
  // rising or falling when they differ by more than the series' own
  // spread (1.4826 x the median absolute deviation about its median, a
  // robust standard deviation) and by more than eps, the smallest change
  // worth a word in the series' unit. Medians, so one spike moves
  // nothing. Fewer than MIN_N samples, or samples covering under half
  // the window, claim no trend: "warming", the baselines' word.
  function trendOf(pts, from, to, eps) {
    var n = pts ? pts.length : 0;
    if (n < MIN_N || !(to > from) || pts[n - 1][0] - pts[0][0] < (to - from) / 2)
      return { word: "warming", d: NaN, spread: NaN, n: n };
    var v = [], i, k = Math.floor(n / 3);
    for (i = 0; i < n; i++) v.push(pts[i][1]);
    var med = median(v), dev = [];
    for (i = 0; i < n; i++) dev.push(Math.abs(v[i] - med));
    var spread = 1.4826 * median(dev);
    var d = median(v.slice(n - k)) - median(v.slice(0, k));
    var bar = Math.max(spread, eps > 0 ? eps : 0);
    return { word: d > bar ? "rising" : d < -bar ? "falling" : "steady", d: d, spread: spread, n: n };
  }

  // A 0/1 series as a strip for G5: CELLS cells over the window, -1
  // where the sensor reported nothing. Points are [t, mean, min, max,
  // n]. worst false is a source's up/down: a bucket counts as up only
  // when it was up throughout (its min), and a cell is 1 only when
  // every bucket in it was, so an outage is never averaged away. worst
  // true is an alarm: a bucket counts as set when it was set at any
  // time (its max), and a cell is 1 when any bucket in it was. And the
  // words: how many buckets were reported, how many were on, and how
  // many times the series went from on to off.
  function stripOf(pts, from, to, worst) {
    var cells = [], i, span = to - from, on = 0, seen = 0, drops = 0, prev = -1;
    for (i = 0; i < CELLS; i++) cells.push(-1);
    for (i = 0; pts && i < pts.length; i++) {
      var c = Math.floor((pts[i][0] - from) / span * CELLS);
      if (!(span > 0) || c < 0 || c >= CELLS) continue;
      var m = worst ? pts[i][3] : pts[i][2];
      var v = (num(m) ? m : pts[i][1]) >= 0.5 ? 1 : 0;
      if (cells[c] < 0) cells[c] = v;
      else if (worst) cells[c] = cells[c] || v;
      else cells[c] = cells[c] && v;
      seen++;
      on += v;
      if (prev === 1 && v === 0) drops++;
      prev = v;
    }
    return { cells: cells, seen: seen, on: on, drops: drops };
  }

  // \u2500\u2500 the tables \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  // A state's mark is a shape and a word, never colour alone (R10).
  var MARK = { "ok": "\u25cf ok", "stale": "\u25d0 stale", "down": "\u2715 down",
               "not_configured": "\u00b7 not configured" };
  var MARK_CLS = { "ok": "health-ok", "stale": "health-bad", "down": "health-bad",
                   "not_configured": "health-unknown" };
  var RANK = { "down": 0, "stale": 1, "ok": 2, "not_configured": 3 };
  function txt(k) { return function (r) { return r[k] || ""; }; }
  function val(k) { return function (r) { return num(r[k]) ? r[k] : null; }; }
  function devText(r) {
    var d = r.desc || "";
    if (r.driver) d += (d ? " " : "") + "(" + r.driver + ")";
    return d;
  }
  function heardText(r) {
    if (r.state === "not_configured") return "-";
    if (!num(r.age_s) || r.age_s < 0) return "never";
    return H.dur(r.age_s) + " ago";
  }
  function rateText(r) {
    if (r.state === "not_configured") return "-";
    return num(r.rate) ? H.fmt(r.rate) + " " + (r.unit || "") + "/s" : "not measured yet";
  }
  var SRC_COLS = [
    { k: "st", label: "STATE", w: 16, min: 8, type: "num", val: function (r) { return RANK[r.state]; } },
    { k: "nm", label: "SOURCE", w: 9, min: 5, type: "text", val: txt("name") },
    { k: "kd", label: "KIND", w: 15, min: 6, type: "text", val: txt("kind") },
    { k: "ep", label: "ENDPOINT", w: 22, min: 8, type: "text", val: txt("endpoint") },
    { k: "dv", label: "DEVICE", w: 26, min: 8, type: "text", val: devText },
    { k: "lh", label: "LAST HEARD", w: 11, min: 6, num: true, type: "num", val: val("age_s") },
    { k: "rt", label: "RATE", w: 16, min: 6, num: true, type: "num", val: val("rate") },
    { k: "er", label: "ERRORS", w: 7, min: 4, num: true, type: "num", val: val("errors") },
    { k: "dt", label: "DETAIL", w: 30, min: 8, type: "text", val: txt("detail") }
  ];
  function usedBy(h) {
    var out = [];
    S.rows.forEach(function (r) { if (r.hw && r.hw === h.key) out.push(r.name); });
    return out.join(", ");
  }
  var HW_COLS = [
    { k: "kd", label: "KIND", w: 16, min: 6, type: "text", val: txt("kind") },
    { k: "ds", label: "RECEIVER", w: 30, min: 8, type: "text", val: function (h) { return h.desc || h.product || ""; } },
    { k: "id", label: "ID", w: 14, min: 6, type: "text", val: function (h) { return (h.bus ? h.bus + " " : "") + (h.id || ""); } },
    { k: "at", label: "AT", w: 12, min: 5, type: "text", val: txt("key") },
    { k: "dr", label: "DRIVER", w: 16, min: 6, type: "text", val: txt("driver") },
    { k: "if", label: "INTERFACES", w: 16, min: 6, type: "text", val: txt("ifaces") },
    { k: "ub", label: "USED BY", w: 12, min: 6, type: "text", val: usedBy },
    { k: "ps", label: "DEVICE SAYS", w: 28, min: 8, type: "text",
      val: function (h) { return [h.vendor, h.product].filter(function (x) { return x; }).join(" "); } }
  ];
  function cell(cls, text) { return el("span", cls, text === "" || text === null || text === undefined ? "-" : text); }
  function tables() {
    if (!window.SlothTables) return;
    if (!ST && $("sy-src-box"))
      ST = window.SlothTables.make({ id: "sy-src", label: "sources", box: $("sy-src-box"),
        head: $("sy-src-thead"), reset: $("sy-src-tools"), redraw: drawSources, cols: SRC_COLS });
    if (!HT && $("sy-hw-box"))
      HT = window.SlothTables.make({ id: "sy-hw", label: "attached receivers", box: $("sy-hw-box"),
        head: $("sy-hw-thead"), reset: $("sy-hw-tools"), redraw: drawHw, cols: HW_COLS });
  }
  function drawSources() {
    var body = clear($("sy-src-rows"));
    var ordered = ST ? ST.sort(S.rows, true) : S.rows.slice();
    ordered.forEach(function (r) {
      var row = el("div", "syrow dt-row " + (r.state === "not_configured" ? "d-dim" : "d-normal"));
      row.appendChild(cell("c-st " + (MARK_CLS[r.state] || "health-unknown"), MARK[r.state] || r.state));
      row.appendChild(cell("c-nm d-bright", r.name));
      row.appendChild(cell("c-kd", r.kind));
      row.appendChild(cell("c-ep", r.endpoint || (r.state === "not_configured" ? "not configured" + (r.flag ? " (" + r.flag + ")" : "") : "")));
      row.appendChild(cell("c-dv", devText(r) || (r.state === "not_configured" ? "" : "not tied to a receiver")));
      row.appendChild(cell("c-lh n", heardText(r)));
      row.appendChild(cell("c-rt n", rateText(r)));
      row.appendChild(cell("c-er n", r.state === "not_configured" || !num(r.errors) ? "-" : H.fmt(r.errors)));
      row.appendChild(cell("c-dt", r.detail));
      body.appendChild(row);
    });
  }
  function drawHw() {
    var body = clear($("sy-hw-rows"));
    var ordered = HT ? HT.sort(S.hw, true) : S.hw.slice();
    ordered.forEach(function (h) {
      var row = el("div", "syrow dt-row d-normal");
      row.appendChild(cell("c-kd d-bright", h.kind));
      row.appendChild(cell("c-ds", h.desc || h.product || (h.known ? "" : "not in sloth's table")));
      row.appendChild(cell("c-id", (h.bus ? h.bus + " " : "") + (h.id || "")));
      row.appendChild(cell("c-at", h.key));
      row.appendChild(cell("c-dr", h.driver));
      row.appendChild(cell("c-if", h.ifaces));
      row.appendChild(cell("c-ub", usedBy(h) || "no source of sloth's"));
      row.appendChild(cell("c-ps d-dim", [h.vendor, h.product].filter(function (x) { return x; }).join(" ")));
      body.appendChild(row);
    });
  }

  // \u2500\u2500 the tiles \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  // A reading the host does not have is said, never drawn as a zero.
  function tile(box, label, value, sub, cls) {
    var t = el("div", "tile sy-tile");
    t.appendChild(el("div", "label", label));
    t.appendChild(el("div", "kpi" + (value === null ? " stale" : "") + (cls ? " " + cls : ""),
                     value === null ? "-" : value));
    t.appendChild(el("div", "sub", value === null ? ABSENT : sub || ""));
    box.appendChild(t);
  }
  function bandWord(b) { return b ? "band: " + b : ""; }
  function drawTiles(j) {
    var box = clear($("sy-tiles")), y = j.system;
    if (!y) return;
    var stale = j.stale ? " stale" : "";
    tile(box, "cpu", num(y.cpu_pct) ? fx(y.cpu_pct, 1) + " %" : null,
         [bandWord(y.cpu_band), num(y.cpu_iowait_pct) ? "iowait " + fx(y.cpu_iowait_pct, 1) + " %" : ""]
           .filter(function (x) { return x; }).join(", "), stale);
    tile(box, "load", num(y.load1) ? fx(y.load1, 2) : null,
         num(y.load5) ? "5 min " + fx(y.load5, 2) + ", 15 min " + fx(y.load15, 2) : "", stale);
    var used = num(y.mem_total_kb) && y.mem_total_kb > 0 ? 100 - 100 * y.mem_avail_kb / y.mem_total_kb : NaN;
    tile(box, "memory", num(used) ? fx(used, 0) + " % used" : null,
         num(used) ? H.fmt(y.mem_avail_kb / 1024) + " MB available of " + H.fmt(y.mem_total_kb / 1024) + " MB" +
                     (y.mem_band ? ", " + bandWord(y.mem_band) : "") : "", stale);
    tile(box, "sloth rss", num(y.rss_kb) ? H.fmt(y.rss_kb / 1024) + " MB" : null, "the sensor process's resident set", stale);
    tile(box, "disk", num(y.disk_free_mb) ? H.fmt(y.disk_free_mb / 1024) + " GB free" : null,
         num(y.disk_free_mb) ? "of " + H.fmt(y.disk_total_mb / 1024) + " GB under the " + (y.disk_for || "output") + " path" +
                               (y.disk_band ? ", " + bandWord(y.disk_band) : "") : "", stale);
    tile(box, "uptime", num(y.uptime_s) ? H.dur(y.uptime_s) : null, "the sensor host's", stale);
    tile(box, "hottest", num(y.temp_max_c) ? fx(cToF(y.temp_max_c), 1) + " \u00b0F" : null,
         (y.temp_max_id || "") + (y.temp_band ? ", " + bandWord(y.temp_band) : ""), stale);
    tile(box, "under-voltage", y.undervolt === 1 ? "\u2715 LOW" : y.undervolt === 0 ? "\u25cf ok" : null,
         y.undervolt === 1 ? "the firmware's under-voltage alarm is set" : "the firmware's alarm is clear",
         (y.undervolt === 1 ? "health-bad" : y.undervolt === 0 ? "health-ok" : "") + stale);
    (j.sensors || []).forEach(function (s) {
      var name = s.label ? s.label + " (" + s.id + ")" : s.id;
      if (s.class === "temp")
        tile(box, "temp " + s.id, num(s.c) ? fx(cToF(s.c), 1) + " \u00b0F" : null, name, stale);
      else if (s.class === "volt")
        tile(box, "volt " + s.id, num(s.v) ? fx(s.v, 3) + " V" : s.alarm === 1 ? "\u2715 LOW" : s.alarm === 0 ? "\u25cf ok" : null,
             name + (s.alarm === 1 ? ", low-voltage alarm set" : s.alarm === 0 ? ", alarm clear" : "") +
             (num(s.v) ? "" : ", an alarm with no reading"), (s.alarm === 1 ? "health-bad" : "") + stale);
      else
        tile(box, "power " + s.id, num(s.capacity) ? s.capacity + " %" : num(s.v) ? fx(s.v, 3) + " V" : s.status || null,
             [s.label, s.status, num(s.capacity) && num(s.v) ? fx(s.v, 3) + " V" : ""]
               .filter(function (x) { return x; }).join(", "), stale);
    });
  }

  // The beacon memory behind EVIL_TWIN's late-arrival signal, one line
  // (JSONL 1.2.0): on, or quiet until a time because the memory
  // overflowed. The time is the sensor's own clock (its batch's ts plus
  // the time it said was left), shown in this browser's zone.
  function recallText(b) {
    if (!b) return "evil-twin late-arrival: not reported by this sensor (older than JSONL 1.2.0)";
    var mem = "beacon memory " + b.slots + " of " + b.max;
    if (b.quiet)
      return "evil-twin late-arrival: quiet until " +
             (num(b.quiet_until) ? new Date(b.quiet_until * 1000).toLocaleString() : "the memory reaches back 24 h") +
             ": the beacon memory overflowed (" + mem +
             (num(b.reach_s) ? ", reaches back " + H.dur(b.reach_s) : "") + ")";
    return "evil-twin late-arrival: on (" + mem +
           (b.overflowed ? "; it overflowed earlier and reaches back " +
                           (num(b.reach_s) ? H.dur(b.reach_s) : "24 h or more") : "") + ")";
  }
  function drawRecall(j) {
    var e = $("sy-recall");
    if (!e) return;
    var b = j.seen ? j.beacon_recall : null;
    e.textContent = j.seen ? recallText(b) : "";
    e.className = "sub" + (b && b.quiet ? " health-bad" : "");
  }

  // \u2500\u2500 /api/sys \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  function draw(j) {
    S.last = j;
    S.rows = (j.sources || []).slice();
    S.hw = (j.receivers || []).slice();
    tables();
    drawSources();
    drawHw();
    drawTiles(j);
    drawRecall(j);
    var cfg = S.rows.filter(function (r) { return r.state !== "not_configured"; }).length;
    var ok = S.rows.filter(function (r) { return r.state === "ok"; }).length;
    if (!j.seen) {
      set("sy-note", "no sys_status record yet");
      set("sy-empty", "The sensor has not reported its host status. Either it is older than JSONL 1.1.0, " +
          "or slothweb is reading a copied sloth.db with no live stream: sloth.db holds none of this, " +
          "so there is nothing to show until a sensor is connected.");
      $("sy-empty").hidden = false;
    } else {
      $("sy-empty").hidden = true;
      set("sy-note", (j.stale ? "STALE: " : "") + "reported " + H.dur(Math.max(0, j.age_s)) + " ago, every " +
          j.interval_s + " s" + (j.stale ? "; the figures below are the last it sent" : ""));
    }
    set("sy-src-cap", "source_status, " + S.rows.length + " sources, " + cfg + " configured, " + ok + " ok; " +
        "state: ok delivering, stale nothing within 60 s (or the decoder's clock stopped), down not open or in error");
    set("sy-hw-cap", "receiver_hw, " + S.hw.length + " attached; USB devices in sloth's table of receiver IDs, wireless " +
        "interfaces and Bluetooth controllers, from sysfs. No serial number is read. A source is tied to a receiver " +
        "only where sysfs says so: a decoder's TCP endpoint is not guessed at");
    set("sy-sys-cap", j.seen ? "sys_status and sys_sensor, sampled every 10 s and reported every " + j.interval_s +
        " s, from /proc and /sys only" : "no data");
  }
  function load() {
    var gen = ++S.gen;
    getJSON("/api/sys").then(function (j) {
      if (gen !== S.gen || !visible()) return;
      draw(j);
      if (Date.now() - S.trendAt >= TREND_MS) trends();
    }).catch(function (e) {
      if (gen !== S.gen) return;
      set("sy-note", "host status unavailable: " + e.message);
    });
  }

  // \u2500\u2500 the trends \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  // One row per series: its name, G1 over the band, the last value, the
  // band's words and the trend's. `share` names a set drawn on one
  // y-scale (R3), `fixed` a scale that is the unit's own (0 to 100 %).
  function rowsWanted(j) {
    var r = [
      { g: "host", name: "cpu", metric: "sys.cpu", key: "", unit: "%", eps: 5, fixed: [0, 100] },
      { g: "host", name: "memory used", metric: "sys.mem_used", key: "", unit: "%", eps: 2, fixed: [0, 100] },
      { g: "host", name: "sloth rss", metric: "sys.rss", key: "", unit: "kB", eps: 1024 },
      { g: "temperature", name: "hottest", metric: "sys.temp", key: "hottest", unit: "\u00b0F", conv: cToF, eps: 1, share: "temp" }
    ];
    (j.sensors || []).forEach(function (s) {
      if (!s.key) return;
      if (s.class === "temp")
        r.push({ g: "temperature", name: s.label || s.id, metric: "sys.temp", key: s.key, unit: "\u00b0F", conv: cToF, eps: 1, share: "temp" });
      else if (num(s.v))
        r.push({ g: "voltage", name: s.label || s.id, metric: "sys.volt", key: s.key, unit: "V", eps: 0.05 });
    });
    if (j.system && num(j.system.undervolt))
      r.push({ g: "voltage", name: "under-voltage alarm", metric: "sys.undervolt", key: "", strip: "alarm" });
    r.push({ g: "stream", name: "capture drops", metric: "sensor.drops", key: "", unit: "frames", eps: 1, counter: true });
    r.push({ g: "stream", name: "records", metric: "records.total", key: "", unit: "rec/s", eps: 1, perSec: true });
    (j.sources || []).forEach(function (s) {
      if (s.state === "not_configured") return;
      r.push({ g: "sources", name: s.name + " up", metric: "source.up", key: s.name, strip: "up" });
      r.push({ g: "sources", name: s.name + " rate", metric: "source.rate", key: s.name,
               unit: (s.unit || "") + "/s", eps: 0.1 });
    });
    return r;
  }
  function tierFor(win) {
    if (win > 86400) return H.storeOn() ? "hour" : null;
    return H.storeOn() ? "minute" : "fine";
  }
  function trendRow(box, w) {
    var row = el("div", "sy-trend");
    row.appendChild(el("span", "sy-tname", w.name));
    var c = el("canvas", w.strip ? "sy-strip" : "spark");
    // ARIA reflection, not an attribute write: the page has none.
    c.ariaLabel = w.name + (w.strip ? " over the window, a cell filled when it held"
                                    : " over the window, over its baseline band");
    row.appendChild(c);
    var words = el("span", "sub sy-twords", "-");
    row.appendChild(words);
    box.appendChild(row);
    return { c: c, words: words };
  }
  function drawSeries(w, ui, s, bl, from, to, shared) {
    var pts = s.points, step = Math.max(60, s.step || 60), bd = H.bands(pts, bl, s.kind, s.step);
    if (w.perSec) {
      pts = pts.map(function (p) { return [p[0], p[1] / s.step]; });
      bd = bd ? bd.map(function (b) { return b ? [b[0] / s.step, b[1] / s.step, b[2] / s.step, b[3] / s.step] : null; }) : null;
    }
    var gw = glyph.win(pts, from, to);
    var id = w.metric + "|" + w.key;
    // R11: grown to hold the data, never shrunk on a refresh; R3: one
    // scale for a set, or the unit's own.
    S.scale[id] = w.fixed ? w.fixed : shared || glyph.scale(pts, bd, S.scale[id] || null);
    glyph.paint(ui.c, glyph.g1(pts, bd, { w: ui.c.clientWidth, h: ui.c.clientHeight, from: gw.from, to: gw.to,
      step: step, sens: H.sens(), scale: S.scale[id] }), H.tok);
    if (!pts.length) { ui.words.textContent = "no data: nothing reported in this window"; return; }
    var last = pts[pts.length - 1][1], t = trendOf(pts, from, to, w.eps);
    var b = bd && bd[bd.length - 1];
    // A counter's bucket sum names its bucket: "3 frames" is one thing
    // per minute and another per hour.
    var unit = w.counter ? w.unit + " per " + glyph.dur(s.step) : w.unit;
    // A temperature is kept and judged in degrees C; only its words are
    // in F (owner, 2026-11-12). The glyph is the series' shape, unitless.
    var cv = w.conv || function (v) { return v; };
    ui.words.textContent = H.fmt(cv(last)) + " " + unit + ", " +
      (b ? "band " + H.fmt(cv(Math.max(0, b[0]))) + " to " + H.fmt(cv(b[1])) : "band warming") + ", " +
      (t.word === "warming" ? "trend warming (" + t.n + " samples)" : t.word + " over " + (gw.shrunk ? gw.text : WINS[String(to - from)] || glyph.dur(to - from)));
    return pts.length;
  }
  function drawStrip(w, ui, s, from, to) {
    var st = stripOf(s.points, from, to, w.strip === "alarm");
    glyph.paint(ui.c, glyph.g5(st.cells, { w: ui.c.clientWidth, h: ui.c.clientHeight, first: -1 }), H.tok);
    if (!st.seen) { ui.words.textContent = "no data: nothing reported in this window"; return 0; }
    var pct = Math.round(100 * st.on / st.seen);
    ui.words.textContent = w.strip === "up"
      ? "up " + pct + " % of the reported time, went down " + st.drops + " time" + (st.drops === 1 ? "" : "s") +
        "; filled: up, empty: stale or down, faint: not reported"
      : (st.on ? "alarm set in " + pct + " % of the reported time" : "alarm never set") +
        "; filled: set, empty: clear, faint: not reported";
    return st.seen;
  }
  function trends() {
    var j = S.last;
    if (!j || !visible()) return;
    S.trendAt = Date.now();
    var gen = ++S.tgen;
    var win = Number($("sy-win").value) || 86400, tier = tierFor(win);
    var box = clear($("sy-trends"));
    if (!tier) {
      set("sy-trend-cap", "no data: a window past 24 h needs the store (slothweb.db); this slothweb keeps 24 h in memory");
      return;
    }
    var step = tier === "hour" ? 3600 : tier === "minute" ? 60 : 10;
    var now = Math.floor(Date.now() / 1000), to = now - now % step + step, from = to - win;
    var want = rowsWanted(j), group = "", n = 0, done = 0;
    // R11 keeps a scale across refreshes, not across windows.
    if (S.scaleOf !== String(win)) { S.scale = {}; S.scaleOf = String(win); }
    var temps = [], tempUi = [];
    function cap() {
      set("sy-trend-cap", glyph.caption({ source: "sys.*, source.*, sensor.drops, records.total", window: WINS[String(win)],
        tier: tier, scale: "temperatures on one scale, cpu and memory 0 to 100 %, the rest each on its own (the units differ)",
        n: n, state: done < want.length ? "loading" : "trend: the last third's median against the first third's, " +
          "past the series' own spread; warming under " + MIN_N + " samples or half the window" }));
    }
    want.forEach(function (w) {
      if (w.g !== group) { group = w.g; box.appendChild(el("div", "label sy-tgroup", group)); }
      var ui = trendRow(box, w);
      Promise.all([seriesOf(w.metric, w.key, tier, from, to), w.strip ? null : baselineOf(w.metric, w.key)])
        .then(function (r) {
          if (gen !== S.tgen) return;
          if (w.strip) n += drawStrip(w, ui, r[0], from, to) || 0;
          else if (w.share) { temps.push({ w: w, s: r[0], bl: r[1] }); tempUi.push(ui); }
          else n += drawSeries(w, ui, r[0], r[1], from, to, null) || 0;
        }).catch(function () {
          if (gen !== S.tgen) return;
          ui.words.textContent = "series unavailable";
        }).then(function () {
          if (gen !== S.tgen) return;
          done++;
          // The shared set draws once every member is in: R3.
          if (done === want.length) {
            var sets = temps.map(function (t) { return { pts: t.s.points, band: null }; });
            var sh = temps.length ? glyph.shared(sets, S.scale.temp || null) : null;
            S.scale.temp = sh;
            temps.forEach(function (t, i) { n += drawSeries(t.w, tempUi[i], t.s, t.bl, from, to, sh) || 0; });
          }
          cap();
        });
    });
    cap();
  }

  function show() {
    if (!H) return;
    if (!S.timer) S.timer = setInterval(function () { if (visible()) load(); }, POLL_MS);
    S.trendAt = 0;
    load();
  }
  function init(h) {
    H = h;
    var w = $("sy-win");
    if (!w) return;
    var kept = H.prefGet("ctl.sy-win");
    if (typeof kept === "string" && WINS[kept]) w.value = kept;
    w.addEventListener("change", function () { H.prefSet("ctl.sy-win", w.value); trends(); });
  }

  window.SlothSysHealth = { init: init, show: show };
})();
