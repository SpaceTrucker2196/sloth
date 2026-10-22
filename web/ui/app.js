// slothweb M2 client: the Overview view (M1) and the Activity view (M2).
// Overview: KPI tiles and the strip from the /events tick, the record
// ticker from /events record events, and /api/live for the alert list,
// the sensor detail and the ticker's backlog. Activity: /api/metrics,
// /api/keys and /api/series drawn on Canvas 2D. Same-origin relative
// paths only; the page's CSP (connect-src 'self') refuses anything else.
//
// Every value that came from the stream is shown with textContent and
// nothing else: a hostname or SSID holding markup is shown as the
// characters it is. Stream values never become a class name, an
// attribute or a URL; record types map to a fixed class table.
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

  fetch("/api/health", { cache: "no-store" })
    .then(function (r) { return r.json(); })
    .then(function (h) {
      set("sock", h.socket);
      set("db", h.db);
      set("store", h.store);
      set("milestone", h.milestone);
    })
    .catch(function () { set("db", "?"); });

  live();
  setInterval(live, 5000);

  // ── views ─────────────────────────────────────────────────────────
  var view = "overview";
  function show(v) {
    view = v;
    $("v-overview").hidden = v !== "overview";
    $("v-activity").hidden = v !== "activity";
    $("nav-overview").className = v === "overview" ? "on" : "go";
    $("nav-activity").className = v === "activity" ? "on" : "go";
    if (v === "activity") activity();
  }
  $("nav-overview").addEventListener("click", function () { show("overview"); });
  $("nav-activity").addEventListener("click", function () { show("activity"); });

  document.addEventListener("keydown", function (e) {
    if (e.target !== document.body) return;
    if (e.key === "[") $("app").classList.toggle("collapsed");
    if (e.key === "1") show("overview");
    if (e.key === "2") show("activity");
  });

  // ── Activity (spec §8.5, M2: no baselines yet) ────────────────────
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
           bg: css("--bg"), k: [] };
    for (var i = 0; i < 8; i++) TH.k.push(css("--k-" + i));
    return TH;
  }
  // src/ip_color.c ip_color_index(): djb2, modulo 8.
  function keyColor(k) {
    var h = 5381;
    for (var i = 0; i < k.length; i++) h = (((h << 5) + h) + k.charCodeAt(i)) >>> 0;
    return theme().k[h % 8];
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

  // One chart: the bucket value as a line, over the bucket's min..max
  // as a band (a gauge's spread inside its bucket; M3 puts the baseline
  // band here instead). Counters draw their per-bucket sum, presence a
  // strip. A gap of more than two steps breaks the line.
  function draw(c, pts, opt) {
    var T = theme();
    var dpr = sizeCanvas(c);
    var g = c.getContext("2d");
    var W = c.width, H = c.height;
    var padL = opt.axes ? 48 * dpr : 2, padB = opt.axes ? 16 * dpr : 2;
    var padT = 4 * dpr, padR = 4 * dpr;
    g.clearRect(0, 0, W, H);
    var lo = 0, hi = 0;
    for (var i = 0; i < pts.length; i++) {
      var p = pts[i];
      var top = opt.kind === "gauge" ? Math.max(p[1], p[3]) : p[1];
      var bot = opt.kind === "gauge" ? Math.min(p[1], p[2]) : p[1];
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
    if (opt.kind === "gauge" && pts.length) {
      g.fillStyle = T.data;
      g.globalAlpha = 0.12;
      var run = [];
      var flush = function () {
        if (run.length < 1) return;
        g.beginPath();
        g.moveTo(X(run[0][0]), Y(run[0][3]));
        for (var a = 1; a < run.length; a++) g.lineTo(X(run[a][0]), Y(run[a][3]));
        for (var b = run.length - 1; b >= 0; b--) g.lineTo(X(run[b][0]), Y(run[b][2]));
        g.closePath();
        g.fill();
        run = [];
      };
      for (i = 0; i < pts.length; i++) {
        if (i && pts[i][0] - pts[i - 1][0] > gapS) flush();
        run.push(pts[i]);
      }
      flush();
      g.globalAlpha = 1;
    }
    g.strokeStyle = opt.color;
    g.lineWidth = Math.max(1, dpr);
    g.beginPath();
    for (i = 0; i < pts.length; i++) {
      var px = X(pts[i][0]), py = Y(pts[i][1]);
      if (!i || pts[i][0] - pts[i - 1][0] > gapS) g.moveTo(px, py);
      else g.lineTo(px, py);
    }
    g.stroke();
  }

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
    series(m.name, key, tier, from, to).then(function (s) {
      if (gen !== A.gen) return;
      A.last = { pts: s.points, from: from, to: to, step: s.step, kind: s.kind };
      set("a-src", tier + " tier, " + s.points.length + " buckets, " + s.source +
          (!A.storeOn && Number($("a-win").value) > 86400 ? "; minute and hour tiers need a WITH_SQLITE build" : ""));
      draw($("a-chart"), s.points, { from: from, to: to, step: s.step, kind: s.kind,
                                     color: theme().ink, axes: true });
    }).catch(function (e) { set("a-src", "error: " + e.message); });
  }

  // Small multiples: one sparkline per key over the last hour, the
  // highest current value first. Sorting by abs(z) needs the M3
  // baseline; until then the loudest key is top left.
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
    var best = L.pts[0];
    for (var i = 1; i < L.pts.length; i++)
      if (Math.abs(L.pts[i][0] - t) < Math.abs(best[0] - t)) best = L.pts[i];
    set("a-hover", hhmmss(best[0]) + "  value " + fmt(best[1]) + "  min " + fmt(best[2]) +
        "  max " + fmt(best[3]) + "  n " + best[4] + "  (no baseline until M3)");
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
})();
