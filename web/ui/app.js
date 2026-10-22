// slothweb M1 client: the Overview view. KPI tiles and the strip from
// the /events tick, the record ticker from /events record events, and
// /api/live for the alert list, the sensor detail and the ticker's
// backlog. Same-origin relative paths only; the page's CSP
// (connect-src 'self') refuses anything else.
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
      set("milestone", h.milestone);
    })
    .catch(function () { set("db", "?"); });

  live();
  setInterval(live, 5000);

  document.addEventListener("keydown", function (e) {
    if (e.target !== document.body) return;
    if (e.key === "[") $("app").classList.toggle("collapsed");
  });
})();
