// slothweb: the Victron tab (2026-11-15, web_victron.h, docs/wiki/victron.md).
// window.SlothVictron, two hooks app.js calls:
//   SlothVictron.init(h)   once, main()'s helpers lent: getJSON (scoped),
//                          errText, shortStamp, tok
//   SlothVictron.show()    when the view shows: loads /api/victron into
//                          the vc-* containers and keeps them current
//                          while the view is visible
// One card per device sloth-va wrote: a battery monitor (V, A, SOC,
// consumed Ah, time to go, alarm), a DC-DC charger (state, error, input
// and output V, off reason), or a device known only by its sessions
// (the last session's outcome and the services it offered). Each card
// says how old its figures are and marks them stale past the route's
// stale_after_s; a small chart per key metric from sloth.db
// (/api/victron/history), each a mean line over its buckets' min..max.
// The strings are the owner's devices' but came through a file another
// account could write: textContent only, no markup sink, no attribute
// written from a value.
(function () {
  "use strict";
  var H = null;
  var POLL_MS = 10000;
  var HIST_MS = 60000;
  var S = { gen: 0, timer: 0, hours: 24, hist: {} };

  function $(id) { return document.getElementById(id); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); return n; }
  function visible() { var v = $("v-victron"); return v && !v.hidden; }
  function stamp(t) { return H && num(t) && t > 0 ? H.shortStamp(t) : "-"; }
  function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }

  // ── the pure half: web/tests/test_victron.c pins these out of the page ──
  // [VED]'s charger states, as sloth-va names them (va_device_state_name()).
  var STATES = { 0: "off", 1: "low power", 2: "fault", 3: "bulk", 4: "absorption",
                 5: "float", 6: "storage", 7: "equalize (manual)", 9: "inverting",
                 11: "power supply", 245: "starting up", 246: "repeated absorption",
                 247: "auto equalize", 248: "battery safe", 252: "external control" };
  function val(d, name) {
    var v = d && d.values && Object.prototype.hasOwnProperty.call(d.values, name) ? d.values[name] : null;
    return v && num(v.v) ? v.v : null;
  }
  function kindOf(d) {
    if (d.record === "battery_monitor" || val(d, "soc_pct") !== null ||
        val(d, "consumed_ah") !== null) return "battery";
    if (d.record === "dcdc_converter" || val(d, "device_state") !== null ||
        val(d, "input_v") !== null) return "dcdc";
    return "other";
  }
  function fx(v, dp, unit) { return v === null ? "-" : v.toFixed(dp) + (unit ? " " + unit : ""); }
  // Time to go in hours and minutes; 0xFFFF is the device's "infinite",
  // which sloth-va leaves absent, so a present value is a real one.
  function ttg(m) {
    if (m === null) return "-";
    var h = Math.floor(m / 60), r = Math.round(m % 60);
    return h + " h " + (r < 10 ? "0" : "") + r + " min";
  }
  function code(v, none) { return v === null ? "-" : v === 0 ? none : "0x" + v.toString(16); }
  function stateName(v) {
    if (v === null) return "-";
    return Object.prototype.hasOwnProperty.call(STATES, v) ? STATES[v] : "state " + v;
  }
  function fields(d) {
    var k = kindOf(d), f = [];
    if (k === "battery") {
      f.push(["voltage", fx(val(d, "voltage_v"), 2, "V")]);
      f.push(["current", fx(val(d, "current_a"), 2, "A")]);
      f.push(["state of charge", fx(val(d, "soc_pct"), 1, "%")]);
      f.push(["consumed", fx(val(d, "consumed_ah"), 1, "Ah")]);
      f.push(["time to go", ttg(val(d, "ttg_min"))]);
      f.push(["alarm", code(val(d, "alarm_reason"), "none")]);
      if (val(d, "power_w") !== null) f.push(["power", fx(val(d, "power_w"), 0, "W")]);
      if (val(d, "aux_voltage_v") !== null) f.push(["starter", fx(val(d, "aux_voltage_v"), 2, "V")]);
      if (val(d, "mid_voltage_v") !== null) f.push(["midpoint", fx(val(d, "mid_voltage_v"), 2, "V")]);
      if (val(d, "temperature_c") !== null) f.push(["temperature", fx(val(d, "temperature_c"), 1, "C")]);
    } else if (k === "dcdc") {
      f.push(["state", stateName(val(d, "device_state"))]);
      f.push(["error", code(val(d, "charger_error"), "none")]);
      f.push(["input", fx(val(d, "input_v"), 2, "V")]);
      f.push(["output", fx(val(d, "output_v"), 2, "V")]);
      f.push(["off reason", code(val(d, "off_reason"), "none")]);
    } else {
      for (var n in d.values || {}) {
        if (!Object.prototype.hasOwnProperty.call(d.values, n)) continue;
        var x = d.values[n];
        if (x && num(x.v)) f.push([n, x.unit ? x.v.toFixed(2) + " " + x.unit : String(x.v)]);
      }
    }
    return f;
  }
  // The metrics a card charts, by kind.
  function charts(d) {
    var k = kindOf(d);
    if (k === "battery") return ["voltage_v", "current_a", "soc_pct"];
    if (k === "dcdc") return ["input_v", "output_v"];
    var out = [];
    for (var n in d.values || {}) {
      if (Object.prototype.hasOwnProperty.call(d.values, n) && d.values[n].unit && out.length < 3)
        out.push(n);
    }
    return out;
  }
  function ageText(d) {
    if (!num(d.age_s)) return "no reading time";
    var a = d.age_s, t = a < 90 ? Math.round(a) + " s" : a < 5400 ? Math.round(a / 60) + " min"
      : a < 172800 ? Math.round(a / 3600) + " h" : Math.round(a / 86400) + " d";
    return (d.stale ? "STALE: last heard " : "last heard ") + t + " ago";
  }
  function sessionText(d) {
    if (!d.sessions) return "no GATT session yet";
    var t = "last GATT session: " + (d.session || "?") + " (" + stamp(d.last_gatt) + ")";
    if (d.services && d.services.length)
      t += "; " + plural(d.services.length, "service", "services") + " offered";
    return t;
  }
  function stateText(j) {
    if (!j) return "not known";
    if (j.out_of_scope) return String(j.reason || "");
    var s = j.sensor;
    if (!s) return "no reader: the sensor has not reported --victron on this connection (the flag is sloth-rf's)";
    var t = "reader " + s.state + (s.missing ? " (file not there yet)" : "") +
      (s.err ? ": " + s.err : "") + "; " + plural(s.devices || 0, "device", "devices") +
      " in the sensor's table";
    if (num(s.bad_lines) && s.bad_lines > 0) t += "; " + plural(s.bad_lines, "line", "lines") + " refused";
    if (num(s.bad_values) && s.bad_values > 0) t += "; " + plural(s.bad_values, "value", "values") + " out of range, left blank";
    if (num(s.table_full) && s.table_full > 0) t += "; " + plural(s.table_full, "record", "records") + " for a 17th device dropped";
    if (s.state !== "live") t += " - figures below may be old";
    if (j.cut) t += "; list cut to fit";
    return t;
  }
  // One chart's marks in glyph.js's form ([kind, x, y, w, h, token]):
  // each bucket's min..max a band, the means a line, a gap past 2.5
  // buckets (R5), dots under five points (R6), the last one marked
  // (R7), a dash for none (R5). The scale is the data's own min..max,
  // not from zero: a battery's 12.8..13.4 V would be flat on a 0-based
  // axis, and the caption says the range.
  function marks(pts, o) {
    var m = [], w = o.w, h = o.h, i;
    if (!pts || !pts.length) { m.push(["dash", w * 0.35, h / 2, w * 0.3, 1, "--faint"]); return m; }
    var lo = Infinity, hi = -Infinity;
    for (i = 0; i < pts.length; i++) {
      if (pts[i][2] < lo) lo = pts[i][2];
      if (pts[i][3] > hi) hi = pts[i][3];
    }
    var pad = (hi - lo) * 0.08;
    if (!(pad > 0)) pad = Math.abs(hi) > 0 ? Math.abs(hi) * 0.02 : 1;
    lo -= pad; hi += pad;
    var from = o.from, to = o.to, step = o.step > 0 ? o.step : 60;
    var X = function (t) { return to > from ? (t - from) / (to - from) * w : 0; };
    var Y = function (v) { return h - (v - lo) / (hi - lo) * h; };
    for (i = 0; i < pts.length; i++) {
      var bx = X(pts[i][0]), bw = Math.max(1, X(pts[i][0] + step) - bx);
      m.push(["band", bx, Y(pts[i][3]), bw, Math.max(1, Y(pts[i][2]) - Y(pts[i][3])), "--data"]);
    }
    var dots = pts.length < 5;
    for (i = 1; i < pts.length; i++) {
      var xa = X(pts[i - 1][0]), xb = X(pts[i][0]);
      if (pts[i][0] - pts[i - 1][0] > step * 2.5) { m.push(["gap", xa, 0, xb - xa, h, "--faint"]); continue; }
      if (dots) continue;
      m.push(["line", xa, Y(pts[i - 1][1]), xb - xa, Y(pts[i][1]) - Y(pts[i - 1][1]), "--tui-normal"]);
    }
    if (dots)
      for (i = 0; i < pts.length - 1; i++) m.push(["dot", X(pts[i][0]), Y(pts[i][1]), 1.5, 1.5, "--tui-normal"]);
    var k = pts.length - 1;
    m.push(["last", X(pts[k][0]), Y(pts[k][1]), 2.5, 2.5, "--ink"]);
    return m;
  }
  function chartCaption(j) {
    if (!j) return "loading";
    if (j.out_of_scope) return "out of scope";
    if (j.have === false) return "sloth.db has no Victron table yet (schema " + j.db_schema + ")";
    var p = j.points || [], lo = Infinity, hi = -Infinity, g = 0;
    for (var i = 0; i < p.length; i++) {
      if (p[i][2] < lo) lo = p[i][2];
      if (p[i][3] > hi) hi = p[i][3];
      g += p[i][5];
    }
    var u = j.unit ? " " + j.unit : "";
    var t = j.metric + ", " + glyph.dur(j.hours * 3600) + ", " + glyph.dur(j.bucket_s) + " buckets";
    if (!p.length) return t + ", no data";
    t += ", " + lo + ".." + hi + u + ", n=" + p.length;
    if (g > 0) t += ", " + g + " of the rows a GATT session's";
    if (j.cut) t += ", oldest cut";
    return t;
  }

  // ── the DOM half ─────────────────────────────────────────────────────
  function histKey(mac, metric) { return mac + "|" + metric + "|" + S.hours; }
  function histPath(mac, metric) {
    return "/api/victron/history?mac=" + encodeURIComponent(mac) + "&metric=" +
      encodeURIComponent(metric) + "&hours=" + S.hours;
  }
  function paintChart(c, cap, j) {
    cap.textContent = chartCaption(j);
    if (!c.clientWidth) return;
    var pts = (j && !j.out_of_scope && j.points) || [];
    var to = j && num(j.now) ? j.now : 0, from = j && num(j.from) ? j.from : 0;
    glyph.paint(c, marks(pts, { w: c.clientWidth, h: c.clientHeight, from: from, to: to,
                                step: j && j.bucket_s }), H.tok);
  }
  function chart(box, mac, metric) {
    var wrap = el("div", "vc-chart");
    var c = el("canvas", "vc-plot");
    var cap = el("div", "vc-cap");
    wrap.appendChild(c);
    wrap.appendChild(cap);
    box.appendChild(wrap);
    var key = histKey(mac, metric), e = S.hist[key];
    if (e && e.j) paintChart(c, cap, e.j); else cap.textContent = "loading " + metric;
    if (e && Date.now() - e.at < HIST_MS) return;
    S.hist[key] = { at: Date.now(), j: e ? e.j : null };
    H.getJSON(histPath(mac, metric)).then(function (j) {
      S.hist[key] = { at: Date.now(), j: j };
      if (c.isConnected) paintChart(c, cap, j);
    }).catch(function (err) {
      if (c.isConnected) cap.textContent = metric + ": " +
        H.errText(err && err.message ? err.message : "error", err && err.body);
    });
  }
  var KIND_WORD = { battery: "battery monitor", dcdc: "DC-DC charger", other: "device" };
  function card(d) {
    var k = kindOf(d);
    var c = el("section", "vc-card" + (d.stale ? " vc-stale" : ""));
    var hd = el("div", "vc-head");
    hd.appendChild(el("span", "vc-model", d.model || KIND_WORD[k]));
    if (d.serial) hd.appendChild(el("span", "vc-serial", d.serial));
    hd.appendChild(el("span", "vc-mac", d.mac));
    c.appendChild(hd);
    var meta = el("div", "vc-meta");
    meta.appendChild(el("span", d.stale ? "vc-age vc-old" : "vc-age", ageText(d)));
    meta.appendChild(el("span", "vc-src", d.values_src ? "values from " +
      (d.values_src === "gatt" ? "a GATT session" : "Instant Readout") : "no values yet"));
    if (num(d.rssi)) meta.appendChild(el("span", "vc-rssi", d.rssi + " dBm"));
    c.appendChild(meta);
    var f = fields(d);
    if (f.length) {
      var dl = el("dl", "vc-vals");
      for (var i = 0; i < f.length; i++) {
        dl.appendChild(el("dt", null, f[i][0]));
        dl.appendChild(el("dd", d.stale ? "vc-old" : null, f[i][1]));
      }
      c.appendChild(dl);
    }
    c.appendChild(el("div", "vc-sess", sessionText(d)));
    if (d.services && d.services.length) {
      var ul = el("ul", "vc-svc");
      for (var s = 0; s < d.services.length; s++) ul.appendChild(el("li", null, d.services[s]));
      c.appendChild(ul);
    }
    var cs = charts(d);
    if (cs.length) {
      var box = el("div", "vc-charts");
      c.appendChild(box);
      for (var m = 0; m < cs.length; m++) chart(box, d.mac, cs[m]);
    }
    return c;
  }

  function draw(j) {
    var st = $("vc-state");
    // #216: the RF daemon's stream not configured outranks "no reader".
    var rf = window.SlothRfStream ? window.SlothRfStream.text(j, "Victron") : "";
    if (st) st.textContent = rf || stateText(j);
    var box = clear($("vc-cards"));
    if (!box) return;
    var ds = (j && !j.out_of_scope && j.devices) || [];
    for (var i = 0; i < ds.length; i++) box.appendChild(card(ds[i]));
  }

  function load() {
    var gen = ++S.gen;
    H.getJSON("/api/victron").then(function (j) {
      if (gen === S.gen) draw(j);
    }).catch(function (e) {
      if (gen !== S.gen) return;
      draw(null);
      var st = $("vc-state");
      if (st) st.textContent = H.errText(e && e.message ? e.message : "error", e && e.body);
    });
  }

  function tick() {
    S.timer = 0;
    if (!visible()) return;
    load();
    S.timer = setTimeout(tick, POLL_MS);
  }

  window.SlothVictron = {
    init: function (h) {
      H = h;
      var sel = $("vc-hours");
      if (sel) sel.addEventListener("change", function () {
        var v = parseInt(sel.value, 10);
        S.hours = v > 0 && v <= 720 ? v : 24;
        load();
      });
    },
    show: function () {
      if (!H) return;
      if (S.timer) clearTimeout(S.timer);
      tick();
    },
    kindOf: kindOf, fields: fields, charts: charts, ttg: ttg, stateName: stateName,
    ageText: ageText, sessionText: sessionText, stateText: stateText, marks: marks,
    chartCaption: chartCaption
  };
})();
