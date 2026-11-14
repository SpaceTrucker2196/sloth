// slothweb: the rtl_433 tab (#208, web_rtl433.h, docs/wiki/rtl433.md).
// window.SlothRtl433, two hooks app.js calls:
//   SlothRtl433.init(h)   once, main()'s helpers lent: getJSON (scoped),
//                         errText, shortStamp
//   SlothRtl433.show()    when the view shows: loads /api/rtl433 into the
//                         r4-* containers and keeps them current while
//                         the view is visible
// One table: the devices a local rtl_433 decodes (car TPMS, weather
// stations, remotes), as sloth reports them: model, id, type, decodes,
// first and last heard, frequency, RSSI, and the readings sloth keeps,
// each in the unit it arrived in.
// Observation only: no row is a finding. Every string shown came over
// the air: textContent only, no markup sink, no attribute written from
// a value.
(function () {
  "use strict";
  var H = null;
  var POLL_MS = 10000;
  var S = { gen: 0, timer: 0 };

  function $(id) { return document.getElementById(id); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); return n; }
  function visible() { var v = $("v-rtl433"); return v && !v.hidden; }
  function stamp(t) { return H && num(t) && t > 0 ? H.shortStamp(t) : "-"; }
  function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }
  function fixed(v, dp, unit) { return num(v) ? v.toFixed(dp) + unit : "-"; }

  // ── the pure half: web/tests/test_rtl433.c pins these out of the page ──
  function stateText(j) {
    if (!j) return "not known";
    if (j.out_of_scope) return String(j.reason || "");
    var s = j.sensor;
    if (!s) return "no decoder: sloth has not reported --rtl433 on this connection";
    var t = "decoder " + s.state + (s.missing ? " (file not there yet)" : "") +
      (s.err ? ": " + s.err : "") + "; " + plural(s.devices || 0, "device", "devices") +
      " in sloth's table";
    if (num(s.bad_lines) && s.bad_lines > 0) t += "; " + plural(s.bad_lines, "line", "lines") + " refused";
    if (num(s.bad_values) && s.bad_values > 0) t += "; " + plural(s.bad_values, "value", "values") + " out of range, left blank";
    if (num(s.evicted) && s.evicted > 0) t += "; " + plural(s.evicted, "device", "devices") + " dropped for the cap";
    if (j.cut) t += "; list cut to fit";
    return t;
  }
  // A reading in the unit of the key it arrived under, never converted.
  function reading(v, unit) { return num(v) ? v.toFixed(1) + (unit ? " " + unit : "") : "-"; }
  function kind(r) { return [r.dev_type, r.subtype].filter(function (x) { return x; }).join(" / "); }
  function cells(r) {
    return [r.model, r.id, kind(r), r.channel || "", r.msgs,
            stamp(r.first_seen), stamp(r.last_seen), fixed(r.freq_mhz, 3, " MHz"),
            fixed(r.rssi, 1, " dB"), reading(r.temperature, r.temp_unit),
            fixed(r.humidity, 0, " %"), reading(r.pressure, r.pres_unit),
            num(r.battery_ok) ? Math.round(r.battery_ok * 100) + " %" : "-"];
  }
  var HEAD = ["model", "id", "type", "channel", "decodes", "first", "last", "freq",
              "rssi", "temp", "humidity", "pressure", "battery"];

  function table(rows) {
    var t = clear($("r4-rows"));
    if (!t) return;
    t.hidden = !rows.length;
    if (!rows.length) return;
    var tr = el("tr");
    for (var i = 0; i < HEAD.length; i++) tr.appendChild(el("th", null, HEAD[i]));
    t.appendChild(tr);
    for (var r = 0; r < rows.length; r++) {
      var c = cells(rows[r]);
      tr = el("tr");
      for (var k = 0; k < c.length; k++) tr.appendChild(el("td", null, c[k]));
      t.appendChild(tr);
    }
  }

  function draw(j) {
    var st = $("r4-state");
    if (st) st.textContent = stateText(j);
    table((j && !j.out_of_scope && j.devices) || []);
  }

  function load() {
    var gen = ++S.gen;
    H.getJSON("/api/rtl433").then(function (j) {
      if (gen === S.gen) draw(j);
    }).catch(function (e) {
      if (gen !== S.gen) return;
      draw(null);
      var st = $("r4-state");
      if (st) st.textContent = H.errText(e && e.message ? e.message : "error", e && e.body);
    });
  }

  function tick() {
    S.timer = 0;
    if (!visible()) return;
    load();
    S.timer = setTimeout(tick, POLL_MS);
  }

  window.SlothRtl433 = {
    init: function (h) { H = h; },
    show: function () {
      if (!H) return;
      if (S.timer) clearTimeout(S.timer);
      tick();
    },
    stateText: stateText, cells: cells, reading: reading
  };
})();
