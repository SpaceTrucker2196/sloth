// slothweb: the Devices view's waterfall (owner 2026-11-19: "add a
// waterfall graph to the devices pages so we can see when devices appear
// and reappear over time"), GET /api/devices/arrivals.
// window.SlothDevWf, two hooks app.js calls:
//   SlothDevWf.init(h)   once, main()'s helpers lent: getJSON (scoped),
//                        errText, fmt, prefGet, prefSet
//   SlothDevWf.show()    when the Devices view shows: loads the answer
//                        and keeps it current (60 s) while visible
// The isometric grid the WiFi and BLE Devices waterfalls draw
// (web/ui/iso.js): the 24 hours of the day across, the days receding,
// today in front; a column's height the devices present in that hour,
// on one scale for the grid; its body stacked bottom up by what each
// had done before: arrived (not present in the 24 hours before), back
// (absent the hour before, present within the 24) and still (present
// the hour before too). An hour still to come is not drawn.
// Every string is drawn with fillText or set with textContent.
(function () {
  "use strict";
  var H = null;
  var REFRESH_MS = 60000;
  var DAYS = [1, 3, 7, 14, 30], DAYS_DFLT = 7;
  // The three kinds, bottom up, and the theme token each is drawn in.
  var KINDS = [
    { k: "arrived", label: "arrived (none in the 24 h before)", tok: "--heat-3", fb: "#ff6a3d" },
    { k: "back", label: "back (absent the hour before)", tok: "--info-1", fb: "#4fc3f7" },
    { k: "still", label: "still here (present the hour before)", tok: "--phosphor-dim", fb: "#2b8f74" }
  ];
  var S = { gen: 0, timer: 0, j: null, st: { off: null, dirty: true, geo: null, hover: null, o: null } };

  function $(id) { return document.getElementById(id); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function visible() { var v = $("v-devices"); return v && !v.hidden; }
  function cssVar(name, fb) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return v && v.trim() ? v.trim() : fb;
  }
  function note(t) { var n = $("d-wf-note"); if (n) n.textContent = t; }
  function pad2(n) { return (n < 10 ? "0" : "") + n; }

  // -- the pure half: web/tests/test_devwf.c pins these out of the page --
  // An hour's column body, bottom up: each kind its share of the devices
  // present; none for an hour with nobody or still to come.
  function segs(j, i, colors) {
    var p = j.present[i];
    if (!num(p) || p <= 0) return null;
    var out = [];
    for (var n = 0; n < KINDS.length; n++) {
      var v = j[KINDS[n].k][i];
      if (num(v) && v > 0) out.push({ f: v / p, color: colors[n] });
    }
    return out.length ? out : null;
  }
  // The index of day k (0 the oldest) and hour c in the answer's arrays.
  function cell(k, c) { return k * 24 + c; }
  function days() {
    var s = $("d-wf-days"), v = s ? Number(s.value) : DAYS_DFLT;
    return DAYS.indexOf(v) >= 0 ? v : DAYS_DFLT;
  }

  function key(colors) {
    var box = $("d-wf-key");
    if (!box || box.childNodes.length) return;
    KINDS.forEach(function (d, n) {
      var it = document.createElement("span"), sw = document.createElement("span");
      it.className = "it"; sw.className = "sw";
      sw.style.background = colors[n];
      it.appendChild(sw);
      it.appendChild(document.createTextNode(d.label));
      box.appendChild(it);
    });
  }

  function draw() {
    var j = S.j, cv = $("d-wf");
    if (!cv || !window.SlothIso) return;
    var colors = KINDS.map(function (d) { return cssVar(d.tok, d.fb); });
    key(colors);
    var nd = j ? j.days : 0, hmax = 0, cols = [];
    if (j) j.present.forEach(function (v) { if (num(v) && v > hmax) hmax = v; });
    for (var c = 0; c < 24; c++) cols.push({ label: pad2(c) + ":00", short: pad2(c) });
    SlothIso.grid(cv, S.st, {
      cols: cols, n: nd, from: j ? j.from : 0, col_s: 86400,
      value: function (k, c) { var v = j.present[cell(k, c)]; return num(v) ? v : null; },
      segments: function (k, c) { return segs(j, cell(k, c), colors); },
      lo: 0, hi: hmax > 0 ? hmax : 1, ticks: hmax > 0 ? [0, hmax / 2, hmax] : [0], unit: "devices",
      fmt: H.fmt, clock: dayWord, sel: null,
      empty: j ? "no device present in the window" : "loading"
    });
  }
  // A day row's name: its date, the sensor's local day.
  function dayWord(ts) {
    var off = S.j && num(S.j.utc_offset_s) ? S.j.utc_offset_s : 0;
    var d = new Date((ts + off) * 1000);
    return d.getUTCFullYear() + "-" + pad2(d.getUTCMonth() + 1) + "-" + pad2(d.getUTCDate());
  }
  function tipLines(at) {
    var j = S.j;
    if (!j || at.k >= j.days || at.c >= 24) return null;
    var i = cell(at.k, at.c), p = j.present[i];
    var out = [[dayWord(j.from + at.k * 86400) + " " + pad2(at.c) + ":00 to " + pad2((at.c + 1) % 24) + ":00"]];
    if (!num(p)) { out.push(["still to come", true]); return out; }
    out.push([H.fmt(p) + " device" + (p === 1 ? "" : "s") + " present"]);
    KINDS.forEach(function (d) { if (num(j[d.k][i]) && j[d.k][i] > 0) out.push([H.fmt(j[d.k][i]) + " " + d.k, true]); });
    return out;
  }

  function load() {
    var gen = ++S.gen;
    H.getJSON("/api/devices/arrivals?days=" + days()).then(function (j) {
      if (gen !== S.gen) return;
      S.j = j;
      note(H.fmt(j.devices) + " device" + (j.devices === 1 ? "" : "s") + " in the window" +
           (j.more ? ", the most recently heard " + H.fmt(j.devices) : "") + "; the sensor's local days");
      draw();
    }).catch(function (e) {
      if (gen !== S.gen) return;
      S.j = null;
      draw();
      note(H.errText(e && e.message ? e.message : "error", e && e.body));
    });
  }
  function tick() {
    S.timer = 0;
    if (!visible()) return;
    load();
    S.timer = setTimeout(tick, REFRESH_MS);
  }

  function wire() {
    var cv = $("d-wf"), sel = $("d-wf-days");
    if (sel) {
      var kept = H.prefGet("devwf.days");
      if (DAYS.indexOf(kept) >= 0) sel.value = String(kept);
      sel.addEventListener("change", function () {
        H.prefSet("devwf.days", days() === DAYS_DFLT ? null : days());
        if (S.timer) clearTimeout(S.timer);
        tick();
      });
    }
    if (!cv) return;
    cv.addEventListener("pointermove", function (ev) {
      var at = SlothIso.at(cv, S.st, ev), lines = at ? tipLines(at) : null;
      S.st.hover = lines ? at : null;
      SlothIso.tip($("d-wf-tip"), lines, ev);
      SlothIso.grid(cv, S.st);
    });
    cv.addEventListener("pointerleave", function (ev) {
      if (!S.st.hover) return;
      S.st.hover = null;
      SlothIso.tip($("d-wf-tip"), null, ev);
      SlothIso.grid(cv, S.st);
    });
    window.addEventListener("resize", function () { if (visible() && S.j) { S.st.dirty = true; draw(); } });
  }

  window.SlothDevWf = {
    init: function (h) { H = h; wire(); },
    show: function () {
      if (!H) return;
      if (S.timer) clearTimeout(S.timer);
      tick();
    },
    segs: segs, cell: cell, KINDS: KINDS
  };
})();
