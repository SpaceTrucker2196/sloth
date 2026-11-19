// slothweb: the Spectrum tab (2026-11-13, web_spectrum.h,
// docs/wiki/sdr-sweep.md). window.SlothSpectrum, one hook app.js calls
// when the view shows:
//   SlothSpectrum.show()   loads /api/spectrum into the spec-* containers
//                          and polls the run's status while one is queued
//                          or running
// The sweep is sloth-sdrsweep's: about a minute of whole sweeps of a
// receiver the operator dedicated. A range (last 3 scans, 1 h, 5 h,
// 12 h, 24 h; GET /api/spectrum?range=) is one row per run from the
// helper's history, each that run's max-hold; before there is any
// history, last 3 scans falls back to the latest run's own sweeps, one
// row each. It is drawn as an isometric waterfall on a plain canvas (no
// library can load under the page's CSP, and none is wanted): frequency
// across, older rows receding up and to the right (by their time in a
// range, so a missing run is a visible gap), height and colour the
// max-hold level.
// Same-origin relative paths only; every string shown goes through
// textContent, and the canvas draws text with fillText. The one write is
// POST /api/spectrum/run, which carries no parameter: the helper's
// settings are the operator's /etc/default/sloth-sdrsweep.
(function () {
  "use strict";
  var POLL_MS = 3000, IDLE_MS = 30000;
  var timer = 0, gen = 0, doc = null, rows = [], st = null, lastState = "";
  var view = { lo: 0, hi: 0, log: true }, drag = null, hover = null, geo = null;
  var RANGES = [["last3", "last 3 scans"], ["1h", "1 h"], ["5h", "5 h"], ["12h", "12 h"], ["24h", "24 h"]];
  var range = "last3", lastEnded = null;

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
  function visible() { var v = $("v-spectrum"); return v && !v.hidden; }
  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return v && v.trim() ? v.trim() : fallback;
  }
  function when(ts) {
    if (!num(ts) || ts <= 0) return "-";
    var d = new Date(ts * 1000), p = function (n) { return (n < 10 ? "0" : "") + n; };
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " +
      p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }
  function clock(ts) {
    var d = new Date(ts * 1000), p = function (n) { return (n < 10 ? "0" : "") + n; };
    return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }
  function mmss(s) { s = Math.max(0, Math.round(s)); return Math.floor(s / 60) + ":" + (s % 60 < 10 ? "0" : "") + (s % 60); }
  function mhz(hz, dp) {
    if (!num(hz)) return "-";
    var m = hz / 1e6;
    if (dp === undefined) dp = m < 30 ? 4 : m < 1000 ? 3 : 2;
    return m.toFixed(dp) + " MHz";
  }

  // ── US frequency allocations (47 CFR 2.106, simplified) ───────────
  // Names for orientation, not a regulatory reference: the table is the
  // United States', and this sensor may be elsewhere (#204 names the
  // region only for APRS). [lo MHz, hi MHz, name, service]; narrower
  // first wins when a frequency sits in two. The service is the lane
  // the allocation chart under the waterfall draws it in (CATS).
  var BANDS = [
    [0.535, 1.705, "AM broadcast", "bc"], [1.8, 2.0, "160 m amateur", "ham"],
    [2.495, 2.505, "WWV 2.5", "sci"], [3.5, 4.0, "80 m amateur", "ham"], [4.995, 5.005, "WWV 5", "sci"],
    [5.3305, 5.4065, "60 m amateur", "ham"], [5.9, 6.2, "49 m SW broadcast", "bc"],
    [7.0, 7.3, "40 m amateur", "ham"], [7.3, 7.45, "41 m SW broadcast", "bc"],
    [9.4, 9.9, "31 m SW broadcast", "bc"], [9.995, 10.005, "WWV 10", "sci"], [10.1, 10.15, "30 m amateur", "ham"],
    [11.6, 12.1, "25 m SW broadcast", "bc"], [13.553, 13.567, "ISM 13.56", "ism"],
    [13.57, 13.87, "22 m SW broadcast", "bc"], [14.0, 14.35, "20 m amateur", "ham"],
    [14.995, 15.005, "WWV 15", "sci"], [15.1, 15.8, "19 m SW broadcast", "bc"],
    [17.48, 17.9, "16 m SW broadcast", "bc"], [18.068, 18.168, "17 m amateur", "ham"],
    [19.995, 20.005, "WWV 20", "sci"], [21.0, 21.45, "15 m amateur", "ham"],
    [21.45, 21.85, "13 m SW broadcast", "bc"], [24.89, 24.99, "12 m amateur", "ham"],
    [25.67, 26.1, "11 m SW broadcast", "bc"], [26.965, 27.405, "CB", "lm"], [28.0, 29.7, "10 m amateur", "ham"],
    [30, 50, "VHF low land mobile", "lm"], [50, 54, "6 m amateur", "ham"], [54, 72, "TV 2-4", "bc"],
    [72, 76, "fixed/mobile, RC", "lm"], [76, 88, "TV 5-6", "bc"], [88, 108, "FM broadcast", "bc"],
    [108, 118, "aero nav (VOR/ILS)", "air"], [118, 137, "airband (AM voice)", "air"],
    [137, 138, "weather satellites", "sat"], [138, 144, "federal", "gov"], [144, 148, "2 m amateur", "ham"],
    [148, 150.8, "federal", "gov"], [150.8, 174, "VHF land mobile", "lm"], [156, 162.025, "marine VHF", "mar"],
    [162.4, 162.55, "NOAA weather radio", "sci"], [174, 216, "TV 7-13", "bc"], [216, 222, "fixed/mobile", "lm"],
    [222, 225, "1.25 m amateur", "ham"], [225, 400, "UHF military air", "air"],
    [400, 406, "met aids, radiosondes", "sci"], [406, 406.1, "406 MHz distress beacons", "air"],
    [406.1, 420, "federal", "gov"], [420, 450, "70 cm amateur", "ham"], [450, 470, "UHF land mobile", "lm"],
    [462.55, 462.725, "GMRS/FRS", "lm"], [467.55, 467.725, "GMRS/FRS", "lm"],
    [470, 608, "TV 14-36", "bc"], [608, 614, "radio astronomy", "sci"], [614, 698, "600 MHz cellular", "cell"],
    [698, 806, "700 MHz cellular, FirstNet", "cell"], [806, 824, "public safety, SMR", "lm"],
    [824, 849, "850 cellular uplink", "cell"], [851, 869, "public safety, SMR", "lm"],
    [869, 894, "850 cellular downlink", "cell"], [896, 901, "900 MHz SMR", "lm"],
    [902, 928, "ISM 915", "ism"], [902, 928, "33 cm amateur", "ham"], [929, 932, "paging", "lm"], [935, 940, "900 MHz SMR", "lm"],
    [960, 1215, "aero radionav (DME/TACAN)", "air"], [1029, 1031, "SSR interrogation 1030", "air"],
    [1087, 1093, "ADS-B / SSR reply 1090", "air"], [1164, 1215, "GNSS L5/E5", "sat"],
    [1215, 1240, "GNSS L2", "sat"], [1240, 1300, "23 cm amateur", "ham"], [1300, 1350, "long-range radar", "gov"],
    [1350, 1400, "federal", "gov"], [1400, 1427, "radio astronomy (H line)", "sci"],
    [1427, 1518, "L-band terrestrial", "lm"], [1525, 1559, "MSS downlink (Inmarsat)", "sat"],
    [1559, 1610, "GNSS L1 (GPS, Galileo, GLONASS)", "sat"], [1610, 1626.5, "MSS (Iridium, Globalstar)", "sat"],
    [1626.5, 1660.5, "MSS uplink", "sat"], [1670, 1675, "met satellites", "sat"],
    [1675, 1710, "met satellites (GOES, HRPT)", "sat"], [1710, 1780, "AWS cellular uplink", "cell"],
    [1850, 1915, "PCS cellular uplink", "cell"], [1930, 1995, "PCS cellular downlink", "cell"]
  ];
  // The allocation chart's lanes, top to bottom: [service, the lane's
  // name at the left, its colour's token]. Amateur first: it is the
  // lane the amateur band charts below open from. The colours are the
  // palette's (--br-*), no new one.
  var CATS = [["ham", "ham", "--br-9"], ["bc", "bcast", "--br-4"], ["air", "aero", "--br-0"],
              ["mar", "marine", "--br-12"], ["lm", "mobile", "--br-2"], ["cell", "cell", "--br-15"],
              ["sat", "sat", "--br-10"], ["ism", "ISM", "--br-1"], ["gov", "fed", "--br-6"],
              ["sci", "sci", "--br-7"]];
  var LANE_H = 11, CHART_TOP = 32;
  function catOf(key) { for (var i = 0; i < CATS.length; i++) if (CATS[i][0] === key) return i; return -1; }
  function bandOf(hz) {
    var m = hz / 1e6, best = null;
    for (var i = 0; i < BANDS.length; i++) {
      var b = BANDS[i];
      if (m >= b[0] && m <= b[1] && (!best || b[1] - b[0] < best[1] - best[0])) best = b;
    }
    return best ? best[2] : "";
  }
  var PRESETS = [["Full", 0, 0], ["HF 0.5-30", 0.5e6, 30e6], ["VHF 30-300", 30e6, 300e6],
                 ["UHF 300-1000", 300e6, 1000e6], ["L-band 1000-2000", 1000e6, 2000e6]];

  function getJSON(path) {
    return fetch(path, { credentials: "same-origin", cache: "no-store" }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
  }

  // ── the document ─────────────────────────────────────────────────
  function decode(b64, n) {
    var s = atob(b64), out = new Uint8Array(n);
    for (var i = 0; i < n && i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  function take(sweep) {
    doc = null; rows = [];
    if (!sweep || !num(sweep.bins) || sweep.bins <= 0 || !Array.isArray(sweep.rows)) return;
    doc = sweep;
    for (var i = 0; i < sweep.rows.length; i++) {
      var r = sweep.rows[i];
      if (!r || typeof r.data !== "string") continue;
      try {
        rows.push({ t: r.t, floor: r.floor, ended: r.ended, rows: r.rows, complete: r.complete,
                    q: decode(r.data, sweep.bins) });
      } catch (e) { /* skipped */ }
    }
    if (!(view.hi > view.lo) || view.lo < doc.f_lo || view.hi > doc.f_hi) { view.lo = doc.f_lo; view.hi = doc.f_hi; }
  }
  function qOff() { return doc && doc.quant && num(doc.quant.offset_db) ? doc.quant.offset_db : -130; }
  function qStep() { return doc && doc.quant && num(doc.quant.step_db) ? doc.quant.step_db : 0.5; }
  function qDb(q) { return q ? qOff() + q * qStep() : null; }

  // ── the frequency axis ───────────────────────────────────────────
  function fracOf(hz) {
    if (view.log) {
      var lo = Math.max(view.lo, 1e3);
      return Math.log(Math.max(hz, lo) / lo) / Math.log(view.hi / lo);
    }
    return (hz - view.lo) / (view.hi - view.lo);
  }
  function hzOf(f) {
    if (view.log) { var lo = Math.max(view.lo, 1e3); return lo * Math.pow(view.hi / lo, f); }
    return view.lo + f * (view.hi - view.lo);
  }
  function ticks() {
    var out = [], span = view.hi - view.lo;
    if (view.log && view.hi / Math.max(view.lo, 1e3) > 20) {
      var steps = [1, 2, 5];
      for (var e = 3; e <= 10; e++)
        for (var k = 0; k < 3; k++) {
          var v = steps[k] * Math.pow(10, e);
          if (v >= view.lo && v <= view.hi) out.push(v);
        }
      return out;
    }
    var raw = span / 8, mag = Math.pow(10, Math.floor(Math.log(raw) / Math.LN10)), step = mag;
    if (raw / mag > 5) step = 10 * mag; else if (raw / mag > 2) step = 5 * mag; else if (raw / mag > 1) step = 2 * mag;
    for (var t = Math.ceil(view.lo / step) * step; t <= view.hi; t += step) out.push(t);
    return out;
  }
  function tickText(hz) { var m = hz / 1e6; return m >= 1 ? String(+m.toPrecision(6)) : (hz / 1e3) + "k"; }

  // ── colour ───────────────────────────────────────────────────────
  // The palette's heat stops and the theme's inks, SlothIso's (iso.js,
  // #224): the WiFi and BLE Devices waterfalls draw with the same.
  var ISO = window.SlothIso;
  var rgbOf = ISO.rgbOf, theme = ISO.theme, css = ISO.css;

  // ── the waterfall ────────────────────────────────────────────────
  // Geometry: the newest row in front, along the bottom; each older one
  // further back, right and up, by its age (a range: rows sit at their
  // time, so a missing run is a gap where it should be) or by its index
  // (the last 3 scans, a single run's sweeps). The depth the rows take
  // grows and the ridge height shrinks with the row count, so 3 rows
  // are tall ridges and 288 a terrain. Painted back to front, each
  // column filled down to its own baseline, so a front ridge hides what
  // is behind it, as a 3-D surface would; past ~24 rows only every few
  // ridges get an outline, so a dense range reads as a surface and not
  // a hairball. The picture is drawn once into an offscreen canvas;
  // hover and drag paint over a copy of it. The projection, the row
  // painter, the hit test and the offscreen copy are SlothIso's
  // (iso.js); the axes, the band strip, the peak labels, the gaps and
  // the zoom are this tab's.
  function levelRange() {
    if (doc && doc._lr) return doc._lr;
    var lo = Infinity, hi = -Infinity, qmax = 0;
    for (var i = 0; i < rows.length; i++) {
      if (num(rows[i].floor)) lo = Math.min(lo, rows[i].floor);
      var q = rows[i].q;
      for (var j = 0; j < q.length; j++) if (q[j] > qmax) qmax = q[j];
    }
    if (qmax) hi = qDb(qmax);
    if (!isFinite(lo)) lo = -110;
    if (!isFinite(hi) || hi < lo + 20) hi = lo + 20;
    var lr = [lo - 3, hi + 2];
    if (doc) doc._lr = lr;
    return lr;
  }
  // The highest level in display bins [a, b] of one row.
  function colMax(q, a, b) {
    var m = 0;
    for (var j = a; j <= b; j++) if (q[j] > m) m = q[j];
    return m;
  }
  function binOf(hz) { return Math.floor((hz - doc.f_lo) / doc.bin_hz); }
  function timed() { return doc && doc.mode === "history" && range !== "last3" && num(doc.from) && num(doc.to) && doc.to > doc.from; }
  // Each row's depth, 0 the front (now, or the newest) to 1 the back.
  function depthOf(i) {
    if (timed()) return Math.max(0, Math.min(1, (doc.to - rows[i].t) / (doc.to - doc.from)));
    return rows.length > 1 ? (rows.length - 1 - i) / (rows.length - 1) : 0;
  }
  function hhmm(ts) {
    var d = new Date(ts * 1000), p = function (n) { return (n < 10 ? "0" : "") + n; };
    return p(d.getHours()) + ":" + p(d.getMinutes());
  }
  // The usual spacing of the runs, and the stretches past 1.8 times it
  // with none: [from, to] pairs, the window's edges included.
  function gaps() {
    var out = [];
    if (!timed()) return out;
    var dt = [];
    for (var i = 1; i < rows.length; i++) dt.push(rows[i].t - rows[i - 1].t);
    dt.sort(function (a, b) { return a - b; });
    var med = dt.length ? Math.max(60, dt[Math.floor(dt.length / 2)]) : 300, lim = med * 1.8;
    var prev = doc.from;
    for (i = 0; i <= rows.length; i++) {
      var t = i < rows.length ? rows[i].t : doc.to;
      if (t - prev > lim) out.push([prev + (i ? med / 2 : 0), t - (i < rows.length ? med / 2 : 0)]);
      prev = t;
    }
    return out;
  }

  var fr = { off: null, dirty: true };
  function invalidate() { fr.dirty = true; }

  function draw() {
    var cv = $("spec-plot");
    if (!cv) return;
    ISO.frame(cv, fr, render, function (g) {
      if (!geo) return;
      var T = theme(g);
      if (drag && drag.x1 !== undefined) {
        g.fillStyle = css(rgbOf(g, T.signal), 0.15);
        g.fillRect(Math.min(drag.x0, drag.x1), geo.top - 10, Math.abs(drag.x1 - drag.x0), geo.base0 - geo.top + 10);
      }
      if (hover) {
        g.strokeStyle = T.signal; g.lineWidth = 1;
        g.beginPath(); g.moveTo(hover.x, hover.oy); g.lineTo(hover.x, hover.oy - geo.RH); g.stroke();
        g.beginPath(); g.moveTo(hover.ox, hover.oy + 0.5); g.lineTo(hover.ox + geo.PW, hover.oy + 0.5); g.stroke();
      }
    });
  }

  function render(cv, dpr, W, Hh) {
    var g = cv.getContext("2d");
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    var T = theme(g);
    g.clearRect(0, 0, W, Hh);
    g.font = "11px " + cssVar("--font-mono", "monospace");
    if (!doc || !rows.length) {
      g.fillStyle = T.muted;
      g.fillText(doc ? "the sweep has no rows" : range === "last3" ? "no sweep yet" :
                 "no run recorded in this range yet (sloth-sdrsweep-auto.timer records one every 5 min)", 16, 24);
      geo = null;
      return;
    }
    var n = rows.length;
    geo = ISO.layout({ W: W, Hh: Hh, n: n, L: 46, R: timed() ? 112 : 70, top: 70, bottom: CHART_TOP + CATS.length * LANE_H + 8, deep: timed() || n > 12 });
    var L = geo.L, PW = geo.PW, DXT = geo.DXT, DYT = geo.DYT, base0 = geo.base0, RH = geo.RH;
    var lr = levelRange(), span = lr[1] - lr[0], i, k;
    geo.lr = lr;
    function ox(d) { return L + d * DXT; }
    function oy(d) { return base0 - d * DYT; }
    // The floor: its two side rails, the gaps where scheduled runs are
    // missing (hatched), and the level scale at left.
    ISO.rails(g, T, geo);
    var gp = gaps();
    for (k = 0; k < gp.length; k++) {
      var d0 = (doc.to - gp[k][1]) / (doc.to - doc.from), d1 = (doc.to - gp[k][0]) / (doc.to - doc.from);
      g.fillStyle = css(rgbOf(g, T.faint), 0.18);
      g.beginPath();
      g.moveTo(ox(d0), oy(d0)); g.lineTo(ox(d0) + PW, oy(d0)); g.lineTo(ox(d1) + PW, oy(d1)); g.lineTo(ox(d1), oy(d1));
      g.closePath(); g.fill();
    }
    g.strokeStyle = T.rule;
    g.fillStyle = T.muted; g.textAlign = "right";
    for (var db0 = Math.ceil(lr[0] / 10) * 10; db0 <= lr[1]; db0 += 10) {
      var yy = base0 - (db0 - lr[0]) / span * RH;
      g.fillText(String(db0), L - 4, yy + 3);
      g.beginPath(); g.moveTo(L - 2, yy); g.lineTo(L, yy); g.stroke();
    }
    g.save(); g.translate(10, base0 - RH / 2); g.rotate(-Math.PI / 2); g.textAlign = "center";
    g.fillText("dBFS (max-hold)", 0, 0); g.restore();
    // Rows, back to front (SlothIso.paint), each column the highest
    // level in its display bins.
    var cols = Math.max(50, Math.floor(PW / (n > 120 ? 2 : 1)));
    var bins = new Array(cols + 1);
    for (var c = 0; c <= cols; c++) bins[c] = Math.max(0, Math.min(doc.bins - 1, binOf(hzOf(c / cols))));
    var lastLabel = -Infinity;
    ISO.paint(g, T, geo, {
      cols: cols, depth: depthOf,
      value: function (idx, c) {
        var a = bins[c], b = Math.max(a, bins[c + 1] - 1), q = colMax(rows[idx].q, a, b);
        return q ? Math.max(0, Math.min(1, (qDb(q) - lr[0]) / span)) : 0;
      },
      after: function (idx, x0, y0) {
        var row = rows[idx];
        if (!timed() && num(row.t) && y0 - lastLabel >= 12) {
          g.fillStyle = T.muted; g.textAlign = "left";
          g.fillText(doc.mode === "history" ? hhmm(row.t) : clock(row.t), x0 + PW + 6, y0 - 2);
          lastLabel = y0;
        }
      }
    });
    // The time axis, over the rows so no ridge hides it: HH:MM at round
    // times a label height apart, and each gap dashed along it.
    g.fillStyle = T.muted; g.textAlign = "left";
    if (timed()) {
      for (k = 0; k < gp.length; k++) {
        var e0 = (doc.to - gp[k][1]) / (doc.to - doc.from), e1 = (doc.to - gp[k][0]) / (doc.to - doc.from);
        g.strokeStyle = T.signal; g.lineWidth = 2; g.setLineDash([3, 3]);
        g.beginPath(); g.moveTo(ox(e0) + PW + 6, oy(e0)); g.lineTo(ox(e1) + PW + 6, oy(e1)); g.stroke();
        g.setLineDash([]); g.lineWidth = 1;
        if (oy(e0) - oy(e1) > 12) {
          g.fillStyle = T.signal; g.textAlign = "left";
          g.fillText("no runs", ox((e0 + e1) / 2) + PW + 52, oy((e0 + e1) / 2) + 3);
        }
      }
      g.fillStyle = T.muted; g.textAlign = "left";
      var spanS = doc.to - doc.from, steps = [5, 10, 15, 30, 60, 120, 180, 240, 360], stepS = 21600;
      for (k = 0; k < steps.length; k++) if (steps[k] * 60 / spanS * DYT >= 16) { stepS = steps[k] * 60; break; }
      // The first whole local minute that is a multiple of the step
      // (local by the Date's own hours and minutes: the page's one
      // offset read is glyph.js's).
      var t0 = Math.ceil(doc.from / 60) * 60, stepM = stepS / 60;
      for (var m = 0; m < stepM; m++, t0 += 60) {
        var dl = new Date(t0 * 1000);
        if ((dl.getHours() * 60 + dl.getMinutes()) % stepM === 0) break;
      }
      for (var t = t0; t <= doc.to; t += stepS) {
        var dd = (doc.to - t) / spanS;
        g.strokeStyle = T.rule;
        g.beginPath(); g.moveTo(ox(dd), oy(dd)); g.lineTo(ox(dd) - 4, oy(dd) + 2);
        g.moveTo(ox(dd) + PW + 4, oy(dd)); g.lineTo(ox(dd) + PW + 9, oy(dd)); g.stroke();
        g.fillText(hhmm(t), ox(dd) + PW + 12, oy(dd) + 3);
      }
    }
    // The frequency axis under the front row, and the band strip.
    g.fillStyle = T.muted; g.strokeStyle = T.rule; g.textAlign = "center";
    var tk = ticks(), lastX = -100;
    for (i = 0; i < tk.length; i++) {
      var tx = L + fracOf(tk[i]) * PW;
      g.beginPath(); g.moveTo(tx, base0); g.lineTo(tx, base0 + 4); g.stroke();
      if (tx - lastX > 40) { g.fillText(tickText(tk[i]), tx, base0 + 15); lastX = tx; }
    }
    g.textAlign = "left"; g.fillText("MHz", L + PW + 6, base0 + 15);
    bandStrip(g, T, L, base0 + CHART_TOP - 8, PW);
    peakLabels(g, T, lr, span);
  }

  // The allocation chart: a lane per service, each allocation in view
  // a block in its service's colour, named where the name fits; a
  // narrower allocation inside a wider one of the same service (GMRS
  // in UHF land mobile) is drawn over it, wider first.
  function bandStrip(g, T, x0, y, PW) {
    var i, c, wide = [];
    for (c = 0; c < CATS.length; c++) {
      var ly0 = y + c * LANE_H;
      g.fillStyle = cssVar(CATS[c][2], T.muted); g.textAlign = "right";
      g.fillText(CATS[c][1], x0 - 4, ly0 + 8.5);
      g.strokeStyle = T.rule;
      g.beginPath(); g.moveTo(x0, ly0 + LANE_H - 0.5); g.lineTo(x0 + PW, ly0 + LANE_H - 0.5); g.stroke();
    }
    for (i = 0; i < BANDS.length; i++) wide.push(BANDS[i]);
    wide.sort(function (p, q) { return (q[1] - q[0]) - (p[1] - p[0]); });
    for (i = 0; i < wide.length; i++) {
      var b = wide[i], lo = b[0] * 1e6, hi = b[1] * 1e6;
      c = catOf(b[3]);
      if (c < 0 || hi < view.lo || lo > view.hi) continue;
      var a = x0 + Math.max(0, fracOf(Math.max(lo, view.lo))) * PW;
      var z = x0 + Math.min(1, fracOf(Math.min(hi, view.hi))) * PW;
      var ly = y + c * LANE_H, bw = Math.max(1.5, z - a), col = cssVar(CATS[c][2], T.data);
      g.fillStyle = css(T.bg, 1); g.fillRect(a, ly, bw, LANE_H - 1);
      g.fillStyle = css(rgbOf(g, col), 0.38); g.fillRect(a, ly, bw, LANE_H - 1);
      g.fillStyle = col; g.fillRect(a, ly, Math.min(bw, 1.5), LANE_H - 1);
      var label = b[2], w = g.measureText(label).width;
      if (bw > w + 6) { g.fillStyle = T.ink; g.textAlign = "left"; g.fillText(label, a + 4, ly + 8.5); }
    }
  }

  // The strongest peaks in view, labelled on the front row: frequency
  // and band; a clock harmonic dashed and marked "?", an internal spur
  // dim and marked "int". Labels do not overlap: a weaker one that
  // would is left to the list below.
  function peaksInView() {
    var p = doc && Array.isArray(doc.peaks) ? doc.peaks : [], out = [];
    for (var i = 0; i < p.length; i++)
      if (p[i] && num(p[i].freq_hz) && p[i].freq_hz >= view.lo && p[i].freq_hz <= view.hi) out.push(p[i]);
    return out;
  }
  function peakLabels(g, T, lr, span) {
    var p = peaksInView().slice().sort(function (a, b) { return (b.snr_peak || 0) - (a.snr_peak || 0); });
    var N = +($("spec-topn") ? $("spec-topn").value : 12) || 12, used = [], drawn = 0;
    for (var i = 0; i < p.length && drawn < N; i++) {
      var x = geo.L + fracOf(p[i].freq_hz) * geo.PW;
      var y = geo.base0 - Math.max(0, Math.min(1, ((p[i].dbfs || lr[0]) - lr[0]) / span)) * geo.RH;
      var mark = p[i].note === "internal" ? " int" : p[i].note === "clock harmonic?" ? " ?" : "";
      var text = (p[i].freq_hz / 1e6).toFixed(3) + mark, band = bandOf(p[i].freq_hz);
      var w = Math.max(g.measureText(text).width, band ? g.measureText(band).width : 0) + 6;
      var lane = 0, ok = false;
      for (; lane < 3 && !ok; lane++) {
        ok = true;
        for (var u = 0; u < used.length; u++) if (used[u][2] === lane && x - w / 2 < used[u][1] && x + w / 2 > used[u][0]) ok = false;
        if (ok) break;
      }
      if (!ok) continue;
      used.push([x - w / 2, x + w / 2, lane]);
      var ly = 14 + lane * 22, internal = p[i].note === "internal", clockh = p[i].note === "clock harmonic?";
      g.strokeStyle = internal ? T.faint : clockh ? T.muted : T.signal;
      g.setLineDash(clockh || internal ? [3, 3] : []);
      g.beginPath(); g.moveTo(x + 0.5, ly + 12); g.lineTo(x + 0.5, y - 2); g.stroke();
      g.setLineDash([]);
      g.textAlign = "center";
      g.fillStyle = internal ? T.faint : clockh ? T.muted : T.ink;
      g.fillText(text, x, ly);
      if (band) { g.fillStyle = T.muted; g.fillText(band, x, ly + 10); }
      drawn++;
    }
  }

  // ── hover and zoom ───────────────────────────────────────────────
  // The row under the pointer: SlothIso.hit, the frontmost whose
  // painted column covers it, else the nearest baseline.
  function onMove(ev) {
    if (!geo || !doc) return;
    var r = ev.currentTarget.getBoundingClientRect(), x = ev.clientX - r.left, y = ev.clientY - r.top;
    if (drag) { drag.x1 = Math.max(geo.L, Math.min(geo.L + geo.PW, x)); draw(); return; }
    var tip = $("spec-tip"), idx = ISO.hit(geo, x, y);
    if (idx < 0) { hover = null; tip.hidden = true; draw(); return; }
    var ox = geo.rowOx[idx], f = (x - ox) / geo.PW, row = rows[idx];
    var hz = hzOf(f), cols = geo.cols, c = Math.min(cols - 1, Math.floor(f * cols));
    var a = Math.max(0, binOf(hzOf(c / cols))), b = Math.max(a, Math.min(doc.bins - 1, binOf(hzOf((c + 1) / cols)) - 1));
    var q = colMax(row.q, a, b), db = qDb(q);
    hover = { x: ox + f * geo.PW, ox: ox, oy: geo.rowOy[idx] };
    clear(tip);
    tip.appendChild(el("div", "", mhz(hz) + (bandOf(hz) ? "  " + bandOf(hz) : "")));
    tip.appendChild(el("div", "", "level " + (db === null ? "below " + qOff() : db.toFixed(1)) + " dBFS" +
      (num(row.floor) && db !== null ? "  SNR " + (db - row.floor).toFixed(1) + " dB" : "")));
    var what = doc.mode === "history" ? "run " + when(row.t) + (num(row.rows) ? ", " + row.rows + " sweeps" : "") +
      (row.complete === false ? ", stopped early" : "") : "row " + (num(row.t) ? clock(row.t) : "-");
    tip.appendChild(el("div", "d-dim", what + "  floor " + (num(row.floor) ? row.floor.toFixed(1) : "-") + " dBFS"));
    var near = doc.mode !== "history" || idx === rows.length - 1 ? nearestPeak(hz, (hzOf((c + 3) / cols) - hzOf((c - 2) / cols))) : null;
    if (near) tip.appendChild(el("div", near.note === "internal" ? "d-dim" : "",
      "peak " + mhz(near.freq_hz) + "  SNR avg " + near.snr_avg + " / peak " + near.snr_peak + " dB" +
      (near.note ? "  (" + near.note + ")" : "")));
    tip.hidden = false;
    var px = Math.min(r.width - 230, Math.max(0, x + 12));
    tip.style.left = px + "px";
    tip.style.top = Math.max(0, y + 12) + "px";
    draw();
  }
  function nearestPeak(hz, tol) {
    var p = peaksInView(), best = null;
    for (var i = 0; i < p.length; i++) {
      var d = Math.abs(p[i].freq_hz - hz);
      if (d <= Math.max(tol, p[i].width_hz || 0) && (!best || d < Math.abs(best.freq_hz - hz))) best = p[i];
    }
    return best;
  }
  function onDown(ev) {
    if (!geo || !doc || ev.button !== 0) return;
    var r = ev.currentTarget.getBoundingClientRect(), x = ev.clientX - r.left;
    if (x < geo.L || x > geo.L + geo.PW) return;
    drag = { x0: x };
  }
  function onUp() {
    if (!drag) return;
    var d = drag;
    drag = null;
    if (d.x1 !== undefined && Math.abs(d.x1 - d.x0) > 4) {
      var a = hzOf((Math.min(d.x0, d.x1) - geo.L) / geo.PW), b = hzOf((Math.max(d.x0, d.x1) - geo.L) / geo.PW);
      if (b - a > doc.bin_hz * 4) { view.lo = a; view.hi = b; preset(-1); invalidate(); }
    }
    draw();
    peakList();
  }
  function onLeave() { hover = null; drag = null; $("spec-tip").hidden = true; draw(); }

  // The preset in force is pressed; a drag-zoom presses none. Not kept:
  // a zoom is a look at one sweep, not a setting.
  function pressed(id, k) {
    var bs = $(id).getElementsByTagName("button");
    for (var i = 0; i < bs.length; i++) {
      var on = i === k;
      bs[i].className = on ? "on" : "go";
      bs[i].ariaPressed = on ? "true" : "false";
    }
  }
  function preset(k) { pressed("spec-zoom", k); }
  function zoomTo(i) {
    if (!doc) return;
    var p = PRESETS[i];
    view.lo = p[1] ? Math.max(doc.f_lo, p[1]) : doc.f_lo;
    view.hi = p[2] ? Math.min(doc.f_hi, p[2]) : doc.f_hi;
    if (!(view.hi > view.lo)) { view.lo = doc.f_lo; view.hi = doc.f_hi; }
    preset(i);
    invalidate();
    draw();
    peakList();
  }

  // ── the range: kept per viewer, like every other control ─────────
  // Through app.js's store (H.prefGet / H.prefSet, slothweb.v1.*), so
  // "reset settings" clears it and a blocked store is the default, last
  // 3 scans, which is kept as no value at all.
  var H = null;
  function rangeLoad() {
    var v = H ? H.prefGet("spectrum.range") : null;
    for (var i = 0; i < RANGES.length; i++) if (RANGES[i][0] === v) return v;
    return "last3";
  }
  function rangeTo(i) {
    range = RANGES[i][0];
    if (H) H.prefSet("spectrum.range", range === "last3" ? null : range);
    pressed("spec-range", i);
    gen++;
    poll(true);
  }

  // ── the peak list: the canvas's words, for every peak in view ────
  function peakList() {
    var box = clear($("spec-peaks")), p = peaksInView();
    set("spec-peaks-count", doc ? p.length + " in view of " + (doc.peaks ? doc.peaks.length : 0) +
      (doc.mode === "history" ? ", the newest run's " + (doc.peaks ? doc.peaks.length : 0) + " strongest" : "") : "");
    if (!p.length) { box.appendChild(el("div", "sub", doc ? "no peak in view" : "")); return; }
    var h = el("div", "specrow dhead");
    ["FREQ MHz", "WIDTH kHz", "SNR avg", "SNR peak", "dBFS", "ROWS", "BAND", "NOTE"].forEach(function (t) { h.appendChild(el("span", "", t)); });
    box.appendChild(h);
    for (var i = 0; i < p.length && i < 400; i++) {
      var r = el("div", "specrow" + (p[i].note === "internal" ? " int" : p[i].note ? " clk" : ""));
      r.appendChild(el("span", "", (p[i].freq_hz / 1e6).toFixed(4)));
      r.appendChild(el("span", "", num(p[i].width_hz) ? (p[i].width_hz / 1e3).toFixed(1) : "-"));
      r.appendChild(el("span", "", num(p[i].snr_avg) ? p[i].snr_avg.toFixed(1) : "-"));
      r.appendChild(el("span", "", num(p[i].snr_peak) ? p[i].snr_peak.toFixed(1) : "-"));
      r.appendChild(el("span", "", num(p[i].dbfs) ? p[i].dbfs.toFixed(1) : "-"));
      r.appendChild(el("span", "", num(p[i].rows) ? p[i].rows : "-"));
      r.appendChild(el("span", "", bandOf(p[i].freq_hz) || "-"));
      r.appendChild(el("span", "", typeof p[i].note === "string" ? p[i].note : ""));
      box.appendChild(r);
    }
  }

  // ── status, the run button, polling ──────────────────────────────
  function statusLine(s) {
    var h = clear($("spec-head")), now = num(s.now) ? s.now : Math.floor(Date.now() / 1000);
    var b = $("spec-run");
    if (!s.installed) {
      h.appendChild(el("span", "", "Spectrum: sloth-sdrsweep is not installed on this sensor (no state directory). docs/wiki/sdr-sweep.md has the recipe."));
      b.disabled = true;
      b.textContent = "Run 1-min sweep";
      return;
    }
    var state = s.state || "idle", line;
    if (s.running) line = "sweeping: row " + ((s.row || 0) + 1) + ", step " + (s.step || 0) + " of " + (s.steps || "?");
    else if (s.queued) line = "queued " + Math.max(0, now - (s.queued_since || now)) + " s ago" +
      (now - (s.queued_since || now) > 30 ? " - nothing has picked it up: is sloth-sdrsweep.path enabled?" : ", waiting for sloth-sdrsweep");
    else if (state === "stale") line = "the last run stopped reporting (helper gone?)";
    else if (state === "failed") line = "the last run failed" + (s.error ? " (" + s.error + ")" : "") + (num(s.ended) ? " at " + when(s.ended) : "");
    else if (state === "stopped") line = "the last run was stopped" + (num(s.ended) ? " at " + when(s.ended) : "");
    else if (state === "done") line = "last run ended " + when(s.ended);
    else line = "no run yet";
    h.appendChild(el("span", s.running || s.queued ? "h1" : state === "failed" || state === "stale" ? "h3" : "", line));
    if (s.antenna) h.appendChild(el("span", "d-dim", "  antenna: " + s.antenna));
    if (s.out_of_scope) h.appendChild(el("span", "d-dim", "  (Local scope: a sweep is radio, not the host's interfaces; switch to Monitor or Hybrid to see it)"));
    b.disabled = !s.can_run;
    if (s.why_not === "cooldown") b.textContent = "next run in " + mmss(s.retry_after || 0);
    else if (s.running) b.textContent = "sweeping...";
    else if (s.queued) b.textContent = "queued...";
    else b.textContent = "Run 1-min sweep";
    b.title = s.can_run ? "start one sweep now (the receiver is taken for about a minute)" :
      s.why_not === "cooldown" ? "one run per cooldown (" + mmss(Math.max(s.cooldown || 0, 120)) + ") so the shared receiver is not monopolised" :
      "a run is " + (s.why_not || "not possible");
  }

  function rangeName() {
    for (var i = 0; i < RANGES.length; i++) if (RANGES[i][0] === range) return RANGES[i][1];
    return range;
  }
  function sweepMeta(fallback) {
    var m = clear($("spec-meta"));
    if (!doc) {
      m.appendChild(el("span", "d-dim", range === "last3" ? "no sweep yet: press Run, or start sloth-sdrsweep.service" :
        rangeName() + ": no run recorded in it yet"));
      return;
    }
    if (doc.mode === "history") {
      var kHz = doc.bin_hz / 1e3;
      m.appendChild(el("span", "", rangeName() + ": " + rows.length + (rows.length === 1 ? " run" : " runs") + ", " +
        when(doc.started) + " to " + clock(doc.ended) + ", each row one run's max-hold per " +
        (kHz >= 1000 ? (kHz / 1e3) + " MHz" : kHz + " kHz") +
        (doc.pool > 1 ? " (" + doc.pool + " bins pooled to fit)" : "")));
      m.appendChild(el("span", "d-dim", "  " + mhz(doc.f_lo, 1) + " to " + mhz(doc.f_hi, 0) + ", antenna " + (doc.antenna || "-") +
        (doc.skipped ? ", " + doc.skipped + " record(s) unreadable or on another span, left out" : "")));
    } else {
      m.appendChild(el("span", "", mhz(doc.f_lo, 1) + " to " + mhz(doc.f_hi, 0) + ", " + rows.length + " rows of " +
        doc.steps + " steps, " + when(doc.started) + " to " + clock(doc.ended) +
        (doc.complete === false ? " (stopped early)" : "")));
      m.appendChild(el("span", "d-dim", "  " + (doc.hardware || doc.driver || "") + (doc.serial ? " " + doc.serial : "") +
        ", antenna " + (doc.antenna || "-") + ", gain " + (doc.gain || "-") + ", " + (doc.sample_rate / 1e6) + " MS/s, " +
        (doc.nfft || "?") + "-point FFT, " + (doc.frames || "?") + " frames a step" +
        (doc.calibrated ? ", spurs calibrated" : ", no spur calibration")));
      if (fallback) m.appendChild(el("span", "d-dim", "  (no run history yet: the latest run's own sweeps, one row each)"));
    }
    set("spec-antenna", doc.antenna || "the configured antenna");
  }

  function show(j, fallback) {
    take(j.sweep);
    invalidate();
    sweepMeta(fallback);
    draw();
    peakList();
    ham();
  }
  // The amateur band charts (hambands.js): the newest row and its peaks.
  function ham() {
    if (!window.SlothHam) return;
    var row = rows.length ? rows[rows.length - 1] : null;
    window.SlothHam.draw({
      doc: doc, row: row, peaks: doc && Array.isArray(doc.peaks) ? doc.peaks : [],
      db: qDb, floor: row && num(row.floor) ? row.floor : null,
      zoom: function (lo, hi) {
        if (!doc) return;
        view.lo = Math.max(doc.f_lo, lo); view.hi = Math.min(doc.f_hi, hi);
        if (!(view.hi > view.lo)) { view.lo = doc.f_lo; view.hi = doc.f_hi; }
        view.log = false; $("spec-log").checked = false;
        preset(-1); invalidate(); draw(); peakList();
        $("spec-plot").scrollIntoView({ block: "center" });
      }
    });
  }
  function poll(full) {
    var g = gen;
    getJSON("/api/spectrum" + (full ? "?range=" + encodeURIComponent(range) : "?status=1")).then(function (j) {
      if (g !== gen) return;
      st = j;
      statusLine(j);
      var s = j.state + (j.running ? "r" : "") + (j.queued ? "q" : "");
      if (full) {
        lastEnded = j.ended;
        // Before the helper kept history, last 3 scans has nothing:
        // show the latest run as the tab always did.
        if (!j.sweep && range === "last3" && !j.out_of_scope) {
          return getJSON("/api/spectrum").then(function (k) {
            if (g !== gen) return;
            show(k, true);
            if (k.sweep_error) set("spec-err", "the latest sweep could not be read: " + k.sweep_error);
            else set("spec-err", "");
            lastState = s;
            schedule(j.running || j.queued ? POLL_MS : j.why_not === "cooldown" ? 1000 : IDLE_MS);
          });
        }
        show(j, false);
      } else if ((lastState && lastState !== s && !j.running && !j.queued) ||
                 (num(j.ended) && num(lastEnded) && j.ended !== lastEnded)) {
        /* A run (the button's or the timer's) has ended: draw it. */
        set("spec-msg", "");
        lastState = s; poll(true); return;
      }
      if (j.sweep_error) set("spec-err", "the latest sweep could not be read: " + j.sweep_error);
      else if (full) set("spec-err", "");
      lastState = s;
      schedule(j.running || j.queued ? POLL_MS : j.why_not === "cooldown" ? 1000 : IDLE_MS);
    }).catch(function (e) {
      if (g !== gen) return;
      set("spec-head", "Spectrum: " + (e && e.message ? e.message : "unavailable"));
      schedule(IDLE_MS);
    });
  }
  function schedule(ms) {
    clearTimeout(timer);
    timer = setTimeout(function () { if (visible()) poll(false); }, ms);
  }

  function run() {
    if (!st || !st.can_run) return;
    var ant = st.antenna || (doc && doc.antenna) || "the configured antenna";
    if (!window.confirm("Run a 1-minute sweep now?\n\nThe receiver (" + ant + ") is taken for about a minute: " +
                        "a decoder sharing it pauses ~1 min (on a sensor where it is shared with APRS, this pauses APRS ~1 min).")) return;
    $("spec-run").disabled = true;
    fetch("/api/spectrum/run", {
      method: "POST", cache: "no-store", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: "{}"
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        set("spec-msg", r.status === 202 ? "queued" : "refused: " + (j.error || ("HTTP " + r.status)) +
          (j.retry_after ? " (retry in " + mmss(j.retry_after) + ")" : ""));
        poll(false);
      });
    }).catch(function (e) { set("spec-msg", "failed: " + (e && e.message ? e.message : "error")); });
  }

  var wired = false;
  function wire() {
    if (wired) return;
    wired = true;
    range = rangeLoad();
    var rg = $("spec-range");
    RANGES.forEach(function (p, i) {
      var b = el("button", "go", p[1]);
      b.type = "button";
      b.addEventListener("click", function () { rangeTo(i); });
      rg.appendChild(b);
      if (p[0] === range) pressed("spec-range", i);
    });
    var z = $("spec-zoom");
    PRESETS.forEach(function (p, i) {
      var b = el("button", "go", p[0]);
      b.type = "button";
      b.addEventListener("click", function () { zoomTo(i); });
      z.appendChild(b);
    });
    preset(0);
    var lg = $("spec-log");
    lg.addEventListener("change", function () { view.log = lg.checked; invalidate(); draw(); });
    $("spec-topn").addEventListener("change", function () { invalidate(); draw(); });
    $("spec-run").addEventListener("click", run);
    var cv = $("spec-plot");
    cv.addEventListener("mousemove", onMove);
    cv.addEventListener("mousedown", onDown);
    cv.addEventListener("mouseup", onUp);
    cv.addEventListener("mouseleave", onLeave);
    cv.addEventListener("dblclick", function () { zoomTo(0); });
    window.addEventListener("resize", function () { if (visible()) { invalidate(); draw(); ham(); } });
  }

  window.SlothSpectrum = {
    // h: app.js's prefGet and prefSet.
    show: function (h) {
      if (h && !H) H = h;
      wire();
      gen++;
      lastState = "";
      poll(true);
    },
    redraw: function () { if (visible()) { invalidate(); draw(); ham(); } },
    BANDS: BANDS, CATS: CATS, bandOf: bandOf
  };
})();
