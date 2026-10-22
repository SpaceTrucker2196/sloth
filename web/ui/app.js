// slothweb M3 client: the Overview view (M1, with M3's baseline band,
// hour-of-week heatmap and top anomalies), the Activity view (M2, with
// M3's baseline band) and the Anomalies view (M3). Overview: KPI tiles
// and the strip from the /events tick, the record ticker from /events
// record events, /api/live for the alert list, the sensor detail and the
// ticker's backlog. Charts: /api/metrics, /api/keys, /api/series and
// /api/baseline on Canvas 2D. Anomalies: /api/anomalies, refreshed on
// the /events anomaly event. Same-origin relative paths only; the page's
// CSP (connect-src 'self') refuses anything else.
//
// Every value that came from the stream is shown with textContent and
// nothing else: a hostname or SSID holding markup is shown as the
// characters it is. Stream values never become a class name, an
// attribute or a URL; record types and anomaly kinds map to fixed
// class tables.
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var TICKER_MAX = 50;
  var TYPE_CLASS = {
    "dns": "t-dns", "tls": "t-tls", "http": "t-http", "quic": "t-quic",
    "icmp": "t-icmp", "arp": "t-arp", "beacon": "t-wifi",
    "wifi_ap": "t-wifi", "wifi_sta": "t-wifi", "probe_client": "t-wifi",
    "alert": "t-alert", "alert.create": "t-alert", "alert.update": "t-alert",
    "alert.escalate": "t-alert", "alert.resolve": "t-alert"
  };
  var SEV_WORD = ["low", "warn", "crit"];
  // §6's kinds, each with a glyph so a card reads in greyscale too.
  var KINDS = ["rate", "new", "hours", "ident", "fanout", "dns", "proto", "sensor"];
  var KIND_GLYPH = {
    "rate": "~", "new": "+", "hours": "@", "ident": "=", "fanout": "<",
    "dns": "?", "proto": "^", "sensor": "!"
  };

  function set(id, text) { $(id).textContent = String(text); }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = String(text);
    return e;
  }

  function typeClass(t) {
    return Object.prototype.hasOwnProperty.call(TYPE_CLASS, t)
      ? TYPE_CLASS[t] : "t-other";
  }

  function kindGlyph(k) {
    return Object.prototype.hasOwnProperty.call(KIND_GLYPH, k) ? KIND_GLYPH[k] : "*";
  }

  function state(cls, word) {
    $("dot").className = "dot " + cls;
    set("conn", word);
  }

  function dur(s) {
    if (s < 60) return s + "s";
    if (s < 3600) return Math.floor(s / 60) + "m" + (s % 60) + "s";
    return Math.floor(s / 3600) + "h" + Math.floor((s % 3600) / 60) + "m";
  }

  function hhmmss(ts) {
    var d = new Date(ts * 1000);
    function two(n) { return (n < 10 ? "0" : "") + n; }
    return two(d.getHours()) + ":" + two(d.getMinutes()) + ":" + two(d.getSeconds());
  }

  function num(v) { return typeof v === "number" && isFinite(v); }

  // ── sensitivity (§5.3: 1.5 to 4 sd, view only) ────────────────────
  // Kept in this browser only; a blocked or absent store just means the
  // default.
  var SENS_KEY = "slothweb.sensitivity";
  var sens = 2;
  try {
    var saved = Number(window.localStorage.getItem(SENS_KEY));
    if (saved >= 1.5 && saved <= 4) sens = saved;
  } catch (e) { /* no storage: the default */ }
  $("sens").value = String(sens);
  set("sens-v", sens.toFixed(1));

  // ── KPIs ──────────────────────────────────────────────────────────
  function kpis(t) {
    if (typeof t.socket === "string") { set("sock", t.socket); set("s-sock", t.socket); }
    var devs = num(t.devices) ? String(t.devices) : "-";
    set("k-devs", devs);
    set("s-devs", devs);
    $("k-devs").className = "kpi" + (t.devices_stale ? " stale" : "");
    set("k-devs-sub", !num(t.devices) ? "waiting for a device pass"
                      : t.devices_stale ? "last known; stream not live"
                      : "in sloth's latest pass");
    var a = t.alerts_open;
    if (a && num(a[0]) && num(a[1]) && num(a[2])) {
      set("k-low", a[0]); set("k-warn", a[1]); set("k-crit", a[2]);
      set("s-alerts", a[0] + a[1] + a[2]);
    }
    if (t.records_s !== undefined && t.records_s !== null) {
      set("k-rate", t.records_s);
      set("s-rate", t.records_s);
    }
    if (num(t.records)) set("k-rate-sub", t.records + " records since start");
    if (typeof t.sensor === "string") {
      set("k-sensor", t.sensor);
      $("k-sensor").className = "kpi health-" +
        (t.sensor === "ok" ? "ok" : t.sensor === "unknown" ? "unknown" : "bad");
    }
    if (num(t.anomalies_open)) {
      set("k-anoms", t.anomalies_open);
      set("s-anoms", t.anomalies_open);
    }
  }

  // ── the ticker ────────────────────────────────────────────────────
  var paused = false;
  var lastSeq = 0;
  var held = 0;

  function addRecord(r) {
    if (!num(r.seq) || r.seq <= lastSeq) return;
    lastSeq = r.seq;
    if (paused) { held++; set("tick-note", held + " held"); return; }
    var li = el("li", typeClass(r.type));
    li.appendChild(el("span", "ts", num(r.ts) ? hhmmss(r.ts) : "-"));
    li.appendChild(el("span", "ty", r.type));
    li.appendChild(el("span", "tx", r.text));
    var list = $("ticker");
    list.insertBefore(li, list.firstChild);
    while (list.childNodes.length > TICKER_MAX) list.removeChild(list.lastChild);
  }

  $("pause").addEventListener("click", function () {
    paused = !paused;
    set("pause", paused ? "resume" : "pause");
    if (!paused) { held = 0; set("tick-note", ""); }
  });

  // ── /api/live ─────────────────────────────────────────────────────
  function alerts(list) {
    var ol = $("alerts");
    while (ol.firstChild) ol.removeChild(ol.firstChild);
    if (!list || !list.length) { ol.appendChild(el("li", "sub", "none since connect")); return; }
    for (var i = 0; i < list.length; i++) {
      var a = list[i];
      var sev = num(a.sev) && a.sev >= 0 && a.sev <= 2 ? a.sev : -1;
      var li = el("li", sev >= 0 ? "sev" + sev : "");
      li.appendChild(el("span", "ts", num(a.ts) ? hhmmss(a.ts) : "-"));
      li.appendChild(el("span", "ty", sev >= 0 ? SEV_WORD[sev] : "?"));
      li.appendChild(el("span", "ty", String(a.type).replace("alert.", "")));
      li.appendChild(el("span", "tx", a.title + "  " + a.detail));
      ol.appendChild(li);
    }
  }

  function sensor(s) {
    if (!s) return;
    var bits = [];
    if (num(s.age_s)) bits.push("report " + dur(s.age_s) + " ago");
    if (s.capture_iface) bits.push("capture " + s.capture_iface +
                                   (s.capture_running ? " running" : " stopped"));
    if (s.monitor_iface) bits.push("monitor " + s.monitor_iface +
                                   (s.monitor_running ? " running" : " stopped"));
    if (s.scope_not_enforced) bits.push("scope " + s.scope);
    set("k-sensor-sub", bits.length ? bits.join(", ") : "no sensor_health yet");
  }

  var first = true;
  function live() {
    fetch("/api/live", { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (l) {
        kpis({ socket: l.socket, devices: l.devices,
               devices_stale: l.devices_stale, records: l.records,
               records_s: l.records_s,
               sensor: l.sensor ? l.sensor.state : undefined,
               alerts_open: l.alerts_open
                 ? [l.alerts_open.low, l.alerts_open.warn, l.alerts_open.crit]
                 : null });
        alerts(l.alerts);
        sensor(l.sensor);
        if (first && l.recent) {
          for (var i = 0; i < l.recent.length; i++) addRecord(l.recent[i]);
        }
        first = false;
      })
      .catch(function () { set("sock", "?"); });
  }

  // ── /events ───────────────────────────────────────────────────────
  var es = new EventSource("/events");
  state("wait", "connecting");
  es.onopen = function () { state("ok", "live"); };
  es.onerror = function () { state("down", "retrying"); };
  var lastTick = 0;
  es.addEventListener("tick", function (ev) {
    var t;
    try { t = JSON.parse(ev.data); } catch (e) { return; }
    // A tick counting from lower than before is a restarted server,
    // whose record numbers start again too.
    if (num(t.seq) && t.seq < lastTick) { lastSeq = 0; first = true; live(); }
    if (num(t.seq)) lastTick = t.seq;
    state("ok", "live");
    set("seq", t.seq);
    set("up", dur(t.uptime_s));
    set("clients", t.sse_clients);
    kpis(t);
  });
  es.addEventListener("record", function (ev) {
    var r;
    try { r = JSON.parse(ev.data); } catch (e) { return; }
    addRecord(r);
  });
  // An episode opened, advanced or closed: the lists are re-read, at
  // most once a second however many arrive.
  var anomTimer = 0;
  es.addEventListener("anomaly", function () {
    if (anomTimer) return;
    anomTimer = setTimeout(function () { anomTimer = 0; anomalies(); }, 1000);
  });

  fetch("/api/health", { cache: "no-store" })
    .then(function (r) { return r.json(); })
    .then(function (h) {
      set("sock", h.socket);
      set("db", h.db);
      set("store", h.store);
      set("milestone", h.milestone);
      if (h.anomaly && h.anomaly.persisted === false)
        set("k-anoms-sub", "in memory only: lost at a restart");
    })
    .catch(function () { set("db", "?"); });

  live();
  setInterval(live, 5000);

  // ── views ─────────────────────────────────────────────────────────
  var VIEWS = ["overview", "activity", "anomalies"];
  var view = "overview";
  function show(v) {
    view = v;
    for (var i = 0; i < VIEWS.length; i++) {
      $("v-" + VIEWS[i]).hidden = v !== VIEWS[i];
      $("nav-" + VIEWS[i]).className = v === VIEWS[i] ? "on" : "go";
    }
    if (v === "activity") activity();
    if (v === "anomalies") anomalies();
    if (v === "overview") overview();
  }
  $("nav-overview").addEventListener("click", function () { show("overview"); });
  $("nav-activity").addEventListener("click", function () { show("activity"); });
  $("nav-anomalies").addEventListener("click", function () { show("anomalies"); });

  document.addEventListener("keydown", function (e) {
    if (e.target !== document.body) return;
    if (e.key === "[") $("app").classList.toggle("collapsed");
    if (e.key === "1") show("overview");
    if (e.key === "2") show("activity");
    if (e.key === "4") show("anomalies");
  });

  // ── drawing ───────────────────────────────────────────────────────
  // Charts are Canvas 2D, coloured from the theme.css tokens read back
  // at run time, so colour still lives in one place. Keys came off the
  // stream but were canonicalised by the server (a MAC, an IP, an
  // interface name, a channel, an alert type); they are shown with
  // textContent or fillText, kept in arrays and referenced by index,
  // and only ever leave as an encodeURIComponent()'d parameter of a
  // same-origin fetch.
  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }
  var TH = null;
  function theme() {
    if (TH) return TH;
    TH = { ink: css("--ink"), muted: css("--muted"), faint: css("--faint"),
           rule: css("--rule"), data: css("--data"), signal: css("--signal"),
           bg: css("--bg"), panel: css("--panel"), k: [], heat: [] };
    for (var i = 0; i < 8; i++) TH.k.push(css("--k-" + i));
    for (i = 0; i < 4; i++) TH.heat.push(css("--heat-" + i));
    return TH;
  }
  // src/ip_color.c ip_color_index(): djb2, modulo 8.
  function keyColor(k) {
    var h = 5381;
    for (var i = 0; i < k.length; i++) h = (((h << 5) + h) + k.charCodeAt(i)) >>> 0;
    return theme().k[h % 8];
  }
  // The heat ramp's thresholds, tui_heat's 0.15 / 0.40 / 0.70.
  function heat(f) {
    var T = theme();
    return f < 0.15 ? T.heat[0] : f < 0.40 ? T.heat[1] : f < 0.70 ? T.heat[2] : T.heat[3];
  }

  function getJSON(path) {
    return fetch(path, { cache: "no-store" }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) throw new Error(j && typeof j.error === "string" ? j.error : String(r.status));
        return j;
      });
    });
  }

  function seriesPath(m, key, tier, from, to) {
    var p = "/api/series?metric=" + encodeURIComponent(m) + "&tier=" + tier +
            "&from=" + from + "&to=" + to;
    if (key !== "") p += "&key=" + encodeURIComponent(key);
    return p;
  }

  // Pages back through "more"/"next_to" until the window is covered.
  function series(m, key, tier, from, to) {
    var all = [], pages = 0, src = "";
    function page(t) {
      return getJSON(seriesPath(m, key, tier, from, t)).then(function (j) {
        src = j.source;
        all = (j.points || []).concat(all);
        pages++;
        if (j.more && num(j.next_to) && j.next_to > from && pages < 12)
          return page(j.next_to);
        return { points: all, kind: j.kind, unit: j.unit, step: j.step, source: src };
      });
    }
    return page(to);
  }

  // The 168 cells of a series (/api/baseline), or null.
  function baseline(m, key) {
    var p = "/api/baseline?metric=" + encodeURIComponent(m);
    if (key !== "") p += "&key=" + encodeURIComponent(key);
    return getJSON(p).catch(function () { return null; });
  }

  // The server's cell for unix second t: its local hour of the week,
  // Monday 00:00 first, from the offset /api/baseline reported.
  function cellOf(t, off) {
    var d = new Date((t + off) * 1000);
    return ((d.getUTCDay() + 6) % 7) * 24 + d.getUTCHours();
  }

  // The band for each point, [lo, hi, mean, sd] or null where the cell
  // is warming. A counter's baseline is per minute; its bucket of step
  // seconds is scaled to match.
  function bands(pts, bl, kind, step) {
    if (!bl || !bl.cells) return null;
    var scale = kind === "counter" ? 60 / step : 1;
    var out = [];
    for (var i = 0; i < pts.length; i++) {
      var c = bl.cells[cellOf(pts[i][0], bl.utc_offset_s || 0)];
      if (!c || c[2] < bl.warm_n) { out.push(null); continue; }
      var mean = c[0] / scale, sd = c[1] / scale;
      out.push([mean - sens * sd, mean + sens * sd, mean, sd]);
    }
    return out;
  }

  var A = { metrics: [], storeOn: false, keys: [], metric: -1, key: 0,
            last: null, timer: 0, gen: 0 };

  function tierFor(win) {
    if (win <= 86400) return "fine";
    if (!A.storeOn) return "fine";
    return win <= 2592000 ? "minute" : "hour";
  }

  function fmt(v) {
    if (!num(v)) return "-";
    var a = Math.abs(v);
    if (a >= 1e9) return (v / 1e9).toFixed(1) + "G";
    if (a >= 1e6) return (v / 1e6).toFixed(1) + "M";
    if (a >= 1e4) return (v / 1e3).toFixed(1) + "k";
    if (a >= 100 || v === Math.round(v)) return String(Math.round(v));
    return v.toFixed(2);
  }

  function sizeCanvas(c) {
    var dpr = window.devicePixelRatio || 1;
    var w = Math.max(1, Math.round(c.clientWidth * dpr));
    var h = Math.max(1, Math.round(c.clientHeight * dpr));
    if (c.width !== w) c.width = w;
    if (c.height !== h) c.height = h;
    return dpr;
  }

  // One chart: the bucket value as a line over the baseline band
  // (mean ± sensitivity x sd for each bucket's hour of the week, in 12%
  // --data, §8.12) when there is one, else over the bucket's min..max
  // (a gauge's spread inside its bucket). A segment out of the band is
  // drawn in the heat ramp, by how far out it is. Presence draws a
  // strip. A gap of more than two steps breaks the line.
  function draw(c, pts, opt) {
    var T = theme();
    var dpr = sizeCanvas(c);
    var g = c.getContext("2d");
    var W = c.width, H = c.height;
    var padL = opt.axes ? 48 * dpr : 2, padB = opt.axes ? 16 * dpr : 2;
    var padT = 4 * dpr, padR = 4 * dpr;
    var band = opt.band || null;
    g.clearRect(0, 0, W, H);
    var lo = 0, hi = 0;
    for (var i = 0; i < pts.length; i++) {
      var p = pts[i];
      var top = opt.kind === "gauge" && !band ? Math.max(p[1], p[3]) : p[1];
      var bot = opt.kind === "gauge" && !band ? Math.min(p[1], p[2]) : p[1];
      if (band && band[i]) { top = Math.max(top, band[i][1]); bot = Math.min(bot, band[i][0]); }
      if (top > hi) hi = top;
      if (bot < lo) lo = bot;
    }
    if (hi === lo) hi = lo + 1;
    var x0 = padL, x1 = W - padR, y0 = H - padB, y1 = padT;
    function X(t) { return x0 + (t - opt.from) / (opt.to - opt.from) * (x1 - x0); }
    function Y(v) { return y0 - (v - lo) / (hi - lo) * (y0 - y1); }
    if (opt.axes) {
      g.strokeStyle = T.rule;
      g.lineWidth = 1;
      g.beginPath(); g.moveTo(x0, y0 + 0.5); g.lineTo(x1, y0 + 0.5); g.stroke();
      g.fillStyle = T.muted;
      g.font = (10 * dpr) + "px " + css("--font-mono");
      g.textBaseline = "top";
      g.fillText(fmt(hi), 2 * dpr, y1);
      g.textBaseline = "bottom";
      g.fillText(fmt(lo), 2 * dpr, y0);
      g.textBaseline = "top";
      g.fillText(hhmmss(opt.from), x0, y0 + 2 * dpr);
      var endTxt = hhmmss(opt.to);
      g.fillText(endTxt, x1 - g.measureText(endTxt).width, y0 + 2 * dpr);
    }
    var gapS = opt.step * 2.5;
    if (opt.kind === "presence") {
      g.fillStyle = opt.color;
      var bw = Math.max(1, (x1 - x0) * opt.step / (opt.to - opt.from));
      for (i = 0; i < pts.length; i++)
        if (pts[i][1] > 0) g.fillRect(X(pts[i][0]), y1, bw, y0 - y1);
      return;
    }
    function fillRuns(loOf, hiOf, ok) {
      var run = [];
      var flush = function () {
        if (run.length < 1) return;
        g.beginPath();
        g.moveTo(X(run[0][0]), Y(hiOf(run[0])));
        for (var a = 1; a < run.length; a++) g.lineTo(X(run[a][0]), Y(hiOf(run[a])));
        for (var b = run.length - 1; b >= 0; b--) g.lineTo(X(run[b][0]), Y(loOf(run[b])));
        g.closePath();
        g.fill();
        run = [];
      };
      for (var k = 0; k < pts.length; k++) {
        if (!ok(k) || (k && pts[k][0] - pts[k - 1][0] > gapS)) flush();
        if (ok(k)) run.push(pts[k].concat([k]));
      }
      flush();
    }
    g.fillStyle = T.data;
    g.globalAlpha = 0.12;
    if (band) {
      fillRuns(function (r) { return band[r[5]][0]; }, function (r) { return band[r[5]][1]; },
               function (k) { return !!band[k]; });
    } else if (opt.kind === "gauge" && pts.length) {
      fillRuns(function (r) { return r[2]; }, function (r) { return r[3]; },
               function () { return true; });
    }
    g.globalAlpha = 1;
    g.lineWidth = Math.max(1, dpr);
    for (i = 1; i < pts.length; i++) {
      if (pts[i][0] - pts[i - 1][0] > gapS) continue;
      var col = opt.color, b = band && band[i];
      if (b && b[3] > 0 && (pts[i][1] > b[1] || pts[i][1] < b[0])) {
        var z = Math.abs(pts[i][1] - b[2]) / b[3];
        col = heat(Math.min(1, (z - sens) / 4 + 0.15));
      }
      g.strokeStyle = col;
      g.beginPath();
      g.moveTo(X(pts[i - 1][0]), Y(pts[i - 1][1]));
      g.lineTo(X(pts[i][0]), Y(pts[i][1]));
      g.stroke();
    }
    if (pts.length === 1) {
      g.fillStyle = opt.color;
      g.fillRect(X(pts[0][0]), Y(pts[0][1]), dpr, dpr);
    }
  }

  // The hour-of-week heatmap (§8.4, §8.12): 7 rows from Monday, 24
  // columns, the heat ramp by the cell's mean against the largest, a
  // warming cell (fewer than warm_n samples) grey and hatched, the
  // current cell outlined in --signal.
  var DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  function heatmap(c, bl) {
    var T = theme();
    var dpr = sizeCanvas(c);
    var g = c.getContext("2d");
    var W = c.width, H = c.height;
    g.clearRect(0, 0, W, H);
    var padL = 32 * dpr, padT = 14 * dpr;
    var cw = (W - padL) / 24, ch = (H - padT) / 7;
    g.font = (9 * dpr) + "px " + css("--font-mono");
    g.fillStyle = T.muted;
    g.textBaseline = "middle";
    for (var d = 0; d < 7; d++) g.fillText(DAYS[d], 0, padT + ch * (d + 0.5));
    g.textBaseline = "top";
    for (var h = 0; h < 24; h += 3) g.fillText(String(h), padL + cw * h, 0);
    if (!bl) return;
    // Never fed: every cell is warming.
    var cells = bl.cells || [];
    var warm = num(bl.warm_n) ? bl.warm_n : 3;
    var max = 0;
    for (var i = 0; i < cells.length; i++)
      if (cells[i][2] >= warm && cells[i][0] > max) max = cells[i][0];
    for (i = 0; i < 168; i++) {
      var x = padL + cw * (i % 24), y = padT + ch * Math.floor(i / 24);
      var cell = cells[i] || [0, 0, 0];
      if (cell[2] < warm) {
        g.fillStyle = T.rule;
        g.fillRect(x + 1, y + 1, cw - 2, ch - 2);
        g.save();
        g.beginPath();
        g.rect(x + 1, y + 1, cw - 2, ch - 2);
        g.clip();
        g.strokeStyle = T.faint;
        g.lineWidth = 1;
        g.beginPath();
        for (var s = -ch; s < cw; s += 4 * dpr) {
          g.moveTo(x + s, y + ch);
          g.lineTo(x + s + ch, y);
        }
        g.stroke();
        g.restore();
        continue;
      }
      g.fillStyle = heat(max > 0 ? cell[0] / max : 0);
      g.fillRect(x + 1, y + 1, cw - 2, ch - 2);
    }
    var nc = bl.now_cell;
    if (num(nc) && nc >= 0 && nc < 168) {
      g.strokeStyle = T.signal;
      g.lineWidth = 2 * dpr;
      g.strokeRect(padL + cw * (nc % 24) + dpr, padT + ch * Math.floor(nc / 24) + dpr,
                   cw - 2 * dpr, ch - 2 * dpr);
    }
  }

  // ── Overview (§8.4) ───────────────────────────────────────────────
  // Throughput is iface.rx_rate of the interface sloth reported most
  // recently; devices, alerts and anomalies are counts with no stored
  // series behind them, so only throughput has a band.
  var O = { key: null, gen: 0 };
  function overview() {
    var gen = ++O.gen;
    getJSON("/api/keys?metric=iface.rx_rate").then(function (j) {
      var ks = j.keys || [];
      if (!ks.length || typeof ks[0].key !== "string") {
        set("o-nvn-note", "no interface seen yet");
        return null;
      }
      O.key = ks[0].key;
      set("k-tp-key", O.key);
      var now = Math.floor(Date.now() / 1000);
      var tier = A.storeOn ? "minute" : "fine";
      var step = tier === "minute" ? 60 : 10;
      var to = now - now % step + step, from = to - 86400;
      return Promise.all([series("iface.rx_rate", O.key, tier, from, to),
                          baseline("iface.rx_rate", O.key)])
        .then(function (r) {
          if (gen !== O.gen) return;
          var s = r[0], bl = r[1];
          var bd = bands(s.points, bl, s.kind, s.step);
          var last = s.points.length ? s.points[s.points.length - 1][1] : NaN;
          set("k-tp", fmt(last) + " B/s");
          var opt = { from: from, to: to, step: s.step, kind: s.kind,
                      color: theme().ink, band: bd };
          opt.axes = false;
          draw($("k-tp-spark"), s.points, opt);
          opt.axes = true;
          draw($("o-nvn"), s.points, opt);
          set("o-nvn-note", "iface.rx_rate " + O.key + ", 24 h, " + tier + " tier" +
              (bd ? "" : "; no baseline yet"));
          heatmap($("o-heat"), bl);
          set("o-heat-note", bl && bl.cells ? "iface.rx_rate " + O.key +
              ", mean B/s by local hour of the sensor host" : "no baseline yet");
        });
    }).catch(function (e) { set("o-nvn-note", "error: " + e.message); });
    anomalies();
  }

  // ── Anomalies (§8.7) ──────────────────────────────────────────────
  var N = { kind: "", gen: 0 };

  (function chips() {
    var box = $("n-chips");
    var all = ["all"].concat(KINDS);
    all.forEach(function (k) {
      var b = el("button", k === "all" ? "on" : "", (k === "all" ? "" : kindGlyph(k) + " ") + k);
      b.type = "button";
      b.addEventListener("click", function () {
        N.kind = k === "all" ? "" : k;
        for (var i = 0; i < box.childNodes.length; i++) box.childNodes[i].className = "";
        b.className = "on";
        anomalies();
      });
      box.appendChild(b);
    });
  })();
  $("n-win").addEventListener("change", function () { anomalies(); });

  function stamp(t) {
    if (!num(t)) return "-";
    var d = new Date(t * 1000);
    return d.toLocaleDateString() + " " + hhmmss(t);
  }

  // A rate episode's |z| is its score / 20 (web_anomaly.c z_score), so
  // the sensitivity hides those under it; the server fires at 3 sd, so
  // a setting below that shows what 3 shows.
  function shown(a) {
    return a.kind !== "rate" || !num(a.score) || a.score >= sens * 20 || a.score >= 100;
  }

  function card(a) {
    var c = el("div", "card " + (a.open ? "open" : "closed"));
    var hd = el("div", "hd");
    hd.appendChild(el("span", "gl", kindGlyph(a.kind)));
    hd.appendChild(el("span", "kd", a.kind + " " + a.rule));
    var ky = el("span", "ky", a.key !== "" ? a.key : "(sensor)");
    if (a.key !== "") ky.style.color = keyColor(a.key);
    hd.appendChild(ky);
    c.appendChild(hd);
    var score = num(a.score) ? Math.max(0, Math.min(100, a.score)) : 0;
    var bar = el("div", "bar");
    var fill = el("i");
    fill.style.width = score + "%";
    fill.style.background = heat(score / 100);
    bar.appendChild(fill);
    c.appendChild(bar);
    c.appendChild(el("div", "ev", a.evidence));
    if (typeof a.metric === "string") {
      var cv = document.createElement("canvas");
      c.appendChild(cv);
      var now = Math.floor(Date.now() / 1000);
      var to = now - now % 10 + 10, from = to - 3600;
      getJSON(seriesPath(a.metric, a.key, "fine", from, to)).then(function (j) {
        draw(cv, j.points || [], { from: from, to: to, step: 10, kind: j.kind,
                                   color: a.key !== "" ? keyColor(a.key) : theme().ink,
                                   axes: false });
      }).catch(function () { /* the card stands without it */ });
    }
    c.appendChild(el("div", "tm", (a.open ? "open" : "closed") + "  score " + score +
                     "  first " + stamp(a.first_seen) + "  last " + stamp(a.last_seen)));
    return c;
  }

  function anomalies() {
    var gen = ++N.gen;
    var now = Math.floor(Date.now() / 1000);
    var win = Number($("n-win").value) || 3600;
    var p = "/api/anomalies?since=" + (now - win);
    if (N.kind) p += "&kind=" + encodeURIComponent(N.kind);
    getJSON(p).then(function (j) {
      if (gen !== N.gen) return;
      var list = (j.anomalies || []).filter(shown);
      var box = $("n-cards");
      while (box.firstChild) box.removeChild(box.firstChild);
      list.forEach(function (a) { box.appendChild(card(a)); });
      set("n-count", list.length + " shown" + (j.more ? ", " + j.omitted + " more on the server" : ""));
      set("n-note", list.length ? "" : "nothing in this window");
      // Overview's top five: open ones, highest score first (the
      // server's order), whatever the chips say.
      var top = $("o-anoms");
      while (top.firstChild) top.removeChild(top.firstChild);
      var open = (j.anomalies || []).filter(function (a) { return a.open && shown(a); });
      if (!open.length) top.appendChild(el("div", "sub", "none open"));
      open.slice(0, 5).forEach(function (a) { top.appendChild(card(a)); });
    }).catch(function (e) { set("n-note", "error: " + e.message); });
  }

  $("sens").addEventListener("input", function () {
    sens = Number($("sens").value) || 2;
    set("sens-v", sens.toFixed(1));
    try { window.localStorage.setItem(SENS_KEY, String(sens)); } catch (e) { /* none */ }
    if (view === "overview") overview();
    if (view === "activity") refresh();
    if (view === "anomalies") anomalies();
  });

  // ── Activity (spec §8.5) ──────────────────────────────────────────
  function selMetric() { return A.metrics[A.metric]; }

  function fillKeys() {
    var m = selMetric();
    var sel = $("a-key");
    while (sel.firstChild) sel.removeChild(sel.firstChild);
    if (!m) return Promise.resolve();
    if (m.keykind === "") {
      A.keys = [""];
      var o = el("option", "", "(global)");
      o.value = "0";
      sel.appendChild(o);
      return Promise.resolve();
    }
    return getJSON("/api/keys?metric=" + encodeURIComponent(m.name)).then(function (j) {
      A.keys = [];
      var ks = j.keys || [];
      for (var i = 0; i < ks.length; i++) if (typeof ks[i].key === "string") A.keys.push(ks[i].key);
      for (i = 0; i < A.keys.length; i++) {
        var op = el("option", "", A.keys[i]);
        op.value = String(i);
        sel.appendChild(op);
      }
      if (A.key >= A.keys.length) A.key = 0;
      sel.value = String(A.key);
      set("a-note", A.keys.length ? (j.total > A.keys.length ? A.keys.length + " of " + j.total + " keys" : "")
                                  : "no " + m.keykind + " seen yet");
    });
  }

  function mainChart() {
    var m = selMetric();
    if (!m || !A.keys.length) { set("a-title", m ? m.name : "-"); return; }
    var key = A.keys[A.key] || "";
    var win = Number($("a-win").value) || 3600;
    var tier = tierFor(win);
    if (tier === "fine" && win > 86400) win = 86400;
    var now = Math.floor(Date.now() / 1000);
    var step = tier === "fine" ? 10 : tier === "minute" ? 60 : 3600;
    var to = now - now % step + step, from = to - win;
    var gen = ++A.gen;
    set("a-title", m.name + (key ? "  " + key : "") + "  (" + m.unit + ")");
    Promise.all([series(m.name, key, tier, from, to), baseline(m.name, key)]).then(function (r) {
      if (gen !== A.gen) return;
      var s = r[0];
      var bd = bands(s.points, r[1], s.kind, s.step);
      A.last = { pts: s.points, from: from, to: to, step: s.step, kind: s.kind, band: bd };
      set("a-src", tier + " tier, " + s.points.length + " buckets, " + s.source +
          (bd ? ", band mean ± " + sens.toFixed(1) + " sd" : ", no baseline yet") +
          (!A.storeOn && Number($("a-win").value) > 86400 ? "; minute and hour tiers need a WITH_SQLITE build" : ""));
      draw($("a-chart"), s.points, { from: from, to: to, step: s.step, kind: s.kind,
                                     color: theme().ink, axes: true, band: bd });
    }).catch(function (e) { set("a-src", "error: " + e.message); });
  }

  // Small multiples: one sparkline per key over the last hour, the
  // highest current value first.
  function multiples() {
    var m = selMetric();
    var box = $("a-multi");
    if (!m) return;
    var keys = A.keys.slice(0, 24);
    var now = Math.floor(Date.now() / 1000);
    var to = now - now % 10 + 10, from = to - 3600;
    var gen = A.gen;
    Promise.all(keys.map(function (k) {
      return getJSON(seriesPath(m.name, k, "fine", from, to))
        .then(function (j) { return { key: k, pts: j.points || [], kind: j.kind }; })
        .catch(function () { return { key: k, pts: [], kind: m.kind }; });
    })).then(function (rows) {
      if (gen !== A.gen) return;
      rows.forEach(function (r) { r.cur = r.pts.length ? r.pts[r.pts.length - 1][1] : 0; });
      rows.sort(function (a, b) { return b.cur - a.cur; });
      while (box.firstChild) box.removeChild(box.firstChild);
      rows.forEach(function (r) {
        var cell = el("div", "cell" + (A.keys[A.key] === r.key ? " on" : ""));
        var nm = el("div", "nm", r.key || "(global)");
        nm.style.color = keyColor(r.key);
        cell.appendChild(nm);
        var cv = document.createElement("canvas");
        cell.appendChild(cv);
        cell.appendChild(el("div", "v", fmt(r.cur) + " " + m.unit));
        cell.addEventListener("click", function () {
          var i = A.keys.indexOf(r.key);
          if (i >= 0) { A.key = i; $("a-key").value = String(i); refresh(); }
        });
        box.appendChild(cell);
        draw(cv, r.pts, { from: from, to: to, step: 10, kind: r.kind,
                          color: keyColor(r.key), axes: false });
      });
      set("a-multi-note", A.keys.length > 24 ? "the 24 most recently seen of " + A.keys.length : "");
    });
  }

  function refresh() {
    if (view !== "activity") return;
    mainChart();
    multiples();
  }

  $("a-chart").addEventListener("mousemove", function (e) {
    var L = A.last;
    if (!L || !L.pts.length) return;
    var c = $("a-chart");
    var r = c.getBoundingClientRect();
    var padL = 48, padR = 4;
    var f = (e.clientX - r.left - padL) / Math.max(1, r.width - padL - padR);
    var t = L.from + f * (L.to - L.from);
    var bi = 0;
    for (var i = 1; i < L.pts.length; i++)
      if (Math.abs(L.pts[i][0] - t) < Math.abs(L.pts[bi][0] - t)) bi = i;
    var best = L.pts[bi], b = L.band && L.band[bi];
    set("a-hover", hhmmss(best[0]) + "  value " + fmt(best[1]) + "  min " + fmt(best[2]) +
        "  max " + fmt(best[3]) + "  n " + best[4] +
        (b ? "  baseline " + fmt(b[2]) + "  z " + (b[3] > 0 ? ((best[1] - b[2]) / b[3]).toFixed(1) : "-")
           : "  (warming: no baseline for this hour yet)"));
  });

  $("a-metric").addEventListener("change", function () {
    A.metric = Number($("a-metric").value) || 0;
    A.key = 0;
    fillKeys().then(refresh);
  });
  $("a-key").addEventListener("change", function () {
    A.key = Number($("a-key").value) || 0;
    refresh();
  });
  $("a-win").addEventListener("change", refresh);

  var started = false;
  function activity() {
    if (started) { fillKeys().then(refresh); return; }
    started = true;
    getJSON("/api/metrics").then(function (j) {
      A.storeOn = !!j.store;
      A.metrics = j.metrics || [];
      var sel = $("a-metric");
      var pick = 0;
      for (var i = 0; i < A.metrics.length; i++) {
        var o = el("option", "", A.metrics[i].name);
        o.value = String(i);
        sel.appendChild(o);
        if (A.metrics[i].name === "iface.rx_rate") pick = i;
      }
      A.metric = pick;
      sel.value = String(pick);
      return fillKeys();
    }).then(refresh).catch(function (e) { set("a-note", "error: " + e.message); });
    A.timer = setInterval(refresh, 10000);
  }

  // The Overview is the first view: learn whether there is a store (for
  // the tier), then draw it, and redraw every minute.
  getJSON("/api/metrics").then(function (j) { A.storeOn = !!j.store; })
    .catch(function () { /* fine tier only */ })
    .then(function () { if (view === "overview") overview(); });
  setInterval(function () { if (view === "overview") overview(); }, 60000);
})();
