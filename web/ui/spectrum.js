// slothweb: the Spectrum tab (2026-11-13, web_spectrum.h,
// docs/wiki/sdr-sweep.md). window.SlothSpectrum, one hook app.js calls
// when the view shows:
//   SlothSpectrum.show()   loads /api/spectrum into the spec-* containers
//                          and polls the run's status while one is queued
//                          or running
// The sweep is sloth-sdrsweep's: about a minute of whole sweeps of a
// receiver the operator dedicated, each sweep one time row. It is drawn
// as an isometric waterfall on a plain canvas (no library can load under
// the page's CSP, and none is wanted): frequency across, older rows
// receding up and to the right, height and colour the max-hold level.
// Same-origin relative paths only; every string shown goes through
// textContent, and the canvas draws text with fillText. The one write is
// POST /api/spectrum/run, which carries no parameter: the helper's
// settings are the operator's /etc/default/sloth-sdrsweep.
(function () {
  "use strict";
  var POLL_MS = 3000, IDLE_MS = 30000;
  var timer = 0, gen = 0, doc = null, rows = [], st = null, lastState = "";
  var view = { lo: 0, hi: 0, log: true }, drag = null, hover = null, geo = null;

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
  // region only for APRS). [lo MHz, hi MHz, name]; narrower first wins
  // when a frequency sits in two.
  var BANDS = [
    [0.535, 1.705, "AM broadcast"], [1.8, 2.0, "160 m amateur"],
    [2.495, 2.505, "WWV 2.5"], [3.5, 4.0, "80 m amateur"], [4.995, 5.005, "WWV 5"],
    [5.3305, 5.4065, "60 m amateur"], [5.9, 6.2, "49 m SW broadcast"],
    [7.0, 7.3, "40 m amateur"], [7.3, 7.45, "41 m SW broadcast"],
    [9.4, 9.9, "31 m SW broadcast"], [9.995, 10.005, "WWV 10"], [10.1, 10.15, "30 m amateur"],
    [11.6, 12.1, "25 m SW broadcast"], [13.553, 13.567, "ISM 13.56"],
    [13.57, 13.87, "22 m SW broadcast"], [14.0, 14.35, "20 m amateur"],
    [14.995, 15.005, "WWV 15"], [15.1, 15.8, "19 m SW broadcast"],
    [17.48, 17.9, "16 m SW broadcast"], [18.068, 18.168, "17 m amateur"],
    [19.995, 20.005, "WWV 20"], [21.0, 21.45, "15 m amateur"],
    [21.45, 21.85, "13 m SW broadcast"], [24.89, 24.99, "12 m amateur"],
    [25.67, 26.1, "11 m SW broadcast"], [26.965, 27.405, "CB"], [28.0, 29.7, "10 m amateur"],
    [30, 50, "VHF low land mobile"], [50, 54, "6 m amateur"], [54, 72, "TV 2-4"],
    [72, 76, "fixed/mobile, RC"], [76, 88, "TV 5-6"], [88, 108, "FM broadcast"],
    [108, 118, "aero nav (VOR/ILS)"], [118, 137, "airband (AM voice)"],
    [137, 138, "weather satellites"], [138, 144, "federal"], [144, 148, "2 m amateur"],
    [148, 150.8, "federal"], [150.8, 174, "VHF land mobile"], [156, 162.025, "marine VHF"],
    [162.4, 162.55, "NOAA weather radio"], [174, 216, "TV 7-13"], [216, 222, "fixed/mobile"],
    [222, 225, "1.25 m amateur"], [225, 400, "UHF military air"],
    [400, 406, "met aids, radiosondes"], [406, 406.1, "406 MHz distress beacons"],
    [406.1, 420, "federal"], [420, 450, "70 cm amateur"], [450, 470, "UHF land mobile"],
    [462.55, 462.725, "GMRS/FRS"], [467.55, 467.725, "GMRS/FRS"],
    [470, 608, "TV 14-36"], [608, 614, "radio astronomy"], [614, 698, "600 MHz cellular"],
    [698, 806, "700 MHz cellular, FirstNet"], [806, 824, "public safety, SMR"],
    [824, 849, "850 cellular uplink"], [851, 869, "public safety, SMR"],
    [869, 894, "850 cellular downlink"], [896, 901, "900 MHz SMR"],
    [902, 928, "ISM 915, 33 cm amateur"], [929, 932, "paging"], [935, 940, "900 MHz SMR"],
    [960, 1215, "aero radionav (DME/TACAN)"], [1029, 1031, "SSR interrogation 1030"],
    [1087, 1093, "ADS-B / SSR reply 1090"], [1164, 1215, "GNSS L5/E5"],
    [1215, 1240, "GNSS L2"], [1240, 1300, "23 cm amateur"], [1300, 1350, "long-range radar"],
    [1350, 1400, "federal"], [1400, 1427, "radio astronomy (H line)"],
    [1427, 1518, "L-band terrestrial"], [1525, 1559, "MSS downlink (Inmarsat)"],
    [1559, 1610, "GNSS L1 (GPS, Galileo, GLONASS)"], [1610, 1626.5, "MSS (Iridium, Globalstar)"],
    [1626.5, 1660.5, "MSS uplink"], [1670, 1675, "met satellites"],
    [1675, 1710, "met satellites (GOES, HRPT)"], [1710, 1780, "AWS cellular uplink"],
    [1850, 1915, "PCS cellular uplink"], [1930, 1995, "PCS cellular downlink"]
  ];
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
      try { rows.push({ t: r.t, floor: r.floor, q: decode(r.data, sweep.bins) }); } catch (e) { /* skipped */ }
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
  // The palette's four heat stops, read from the theme at each draw so
  // the light theme gets its own; interpolated through a 1x1 canvas.
  function rgbOf(g, c) {
    g.fillStyle = "#000"; g.fillStyle = c;
    var s = g.fillStyle;
    if (s.charAt(0) === "#") return [parseInt(s.substr(1, 2), 16), parseInt(s.substr(3, 2), 16), parseInt(s.substr(5, 2), 16)];
    var m = s.match(/(\d+(\.\d+)?)/g);
    return m ? [+m[0], +m[1], +m[2]] : [128, 128, 128];
  }
  function theme(g) {
    return {
      heat: [rgbOf(g, cssVar("--heat-0", "#2b8f74")), rgbOf(g, cssVar("--heat-1", "#6bffcc")),
             rgbOf(g, cssVar("--heat-2", "#ff8c26")), rgbOf(g, cssVar("--heat-3", "#ff3f3f"))],
      bg: rgbOf(g, cssVar("--panel", "#0e0817")),
      ink: cssVar("--ink", "#e8e2f2"), muted: cssVar("--muted", "#8a82a0"),
      rule: cssVar("--rule", "#163a30"), signal: cssVar("--signal", "#ff8c26"),
      data: cssVar("--data", "#4cebff"), faint: cssVar("--faint", "#5a536e")
    };
  }
  function mix(a, b, t) { return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t]; }
  function heatRGB(T, f) {
    f = Math.max(0, Math.min(1, f));
    var x = f * 3, i = Math.min(2, Math.floor(x));
    return mix(T.heat[i], T.heat[i + 1], x - i);
  }
  function css(c, a) {
    return "rgba(" + Math.round(c[0]) + "," + Math.round(c[1]) + "," + Math.round(c[2]) + "," + (a === undefined ? 1 : a) + ")";
  }

  // ── the waterfall ────────────────────────────────────────────────
  // Geometry: the newest row in front, along the bottom; each older one
  // DX right and DY up. Painted back to front, so a front ridge hides
  // what is behind it, as a 3-D surface would.
  function levelRange() {
    var lo = Infinity, hi = -Infinity;
    for (var i = 0; i < rows.length; i++) {
      if (num(rows[i].floor)) lo = Math.min(lo, rows[i].floor);
      var q = rows[i].q;
      for (var j = 0; j < q.length; j++) if (q[j] && qDb(q[j]) > hi) hi = qDb(q[j]);
    }
    if (!isFinite(lo)) lo = -110;
    if (!isFinite(hi) || hi < lo + 20) hi = lo + 20;
    return [lo - 3, hi + 2];
  }
  // The highest level in display bins [a, b] of one row.
  function colMax(q, a, b) {
    var m = 0;
    for (var j = a; j <= b; j++) if (q[j] > m) m = q[j];
    return m;
  }
  function binOf(hz) { return Math.floor((hz - doc.f_lo) / doc.bin_hz); }

  function draw() {
    var cv = $("spec-plot");
    if (!cv) return;
    var dpr = window.devicePixelRatio || 1, W = cv.clientWidth || 800, Hh = cv.clientHeight || 460;
    if (cv.width !== Math.round(W * dpr) || cv.height !== Math.round(Hh * dpr)) {
      cv.width = Math.round(W * dpr); cv.height = Math.round(Hh * dpr);
    }
    var g = cv.getContext("2d");
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    var T = theme(g);
    g.clearRect(0, 0, W, Hh);
    g.font = "11px " + cssVar("--font-mono", "monospace");
    if (!doc || !rows.length) {
      g.fillStyle = T.muted;
      g.fillText(doc ? "the sweep has no rows" : "no sweep yet", 16, 24);
      geo = null;
      return;
    }
    var n = rows.length, L = 46, R = 70, top = 70, bottom = 54;
    var DX = Math.min(28, (W - L - R) * 0.04), DY = Math.min(30, (Hh - top - bottom) * 0.12);
    var PW = Math.max(100, W - L - R - DX * (n - 1)), base0 = Hh - bottom;
    var RH = Math.max(60, base0 - top - DY * (n - 1));
    var lr = levelRange(), span = lr[1] - lr[0];
    geo = { L: L, PW: PW, DX: DX, DY: DY, base0: base0, RH: RH, n: n, lr: lr };
    // The floor grid: each row's baseline, and the level scale at left.
    g.strokeStyle = T.rule; g.lineWidth = 1;
    for (var k = 0; k < n; k++) {
      var by = base0 - k * DY + 0.5, bx = L + k * DX;
      g.beginPath(); g.moveTo(bx, by); g.lineTo(bx + PW, by); g.stroke();
    }
    g.beginPath(); g.moveTo(L, base0); g.lineTo(L + (n - 1) * DX, base0 - (n - 1) * DY);
    g.moveTo(L + PW, base0); g.lineTo(L + PW + (n - 1) * DX, base0 - (n - 1) * DY); g.stroke();
    g.fillStyle = T.muted; g.textAlign = "right";
    for (var d = Math.ceil(lr[0] / 10) * 10; d <= lr[1]; d += 10) {
      var yy = base0 - (d - lr[0]) / span * RH;
      g.fillText(String(d), L - 4, yy + 3);
      g.beginPath(); g.moveTo(L - 2, yy); g.lineTo(L, yy); g.stroke();
    }
    g.save(); g.translate(10, base0 - RH / 2); g.rotate(-Math.PI / 2); g.textAlign = "center";
    g.fillText("dBFS (max-hold)", 0, 0); g.restore();
    // Rows, back (oldest) to front (newest).
    var cols = Math.max(50, Math.floor(PW));
    var bins = new Array(cols + 1);
    for (var c = 0; c <= cols; c++) bins[c] = Math.max(0, Math.min(doc.bins - 1, binOf(hzOf(c / cols))));
    for (k = n - 1; k >= 0; k--) {
      var row = rows[n - 1 - k], ox = L + k * DX, oy = base0 - k * DY, ridge = [];
      for (c = 0; c < cols; c++) {
        var a = bins[c], b = Math.max(a, bins[c + 1] - 1);
        var q = colMax(row.q, a, b), db = q ? qDb(q) : lr[0];
        var f = Math.max(0, Math.min(1, (db - lr[0]) / span));
        ridge.push(f);
        var x = ox + c * PW / cols, w = PW / cols + 0.6, hpx = f * RH;
        // The column: the heat colour of its level, darkened toward the
        // panel at the bottom so the surface reads as a solid.
        g.fillStyle = css(mix(T.bg, heatRGB(T, f), 0.35 + 0.65 * f));
        g.fillRect(x, oy - hpx, w, hpx);
      }
      g.beginPath();
      for (c = 0; c < cols; c++) {
        var px = ox + (c + 0.5) * PW / cols, py = oy - ridge[c] * RH;
        if (c) g.lineTo(px, py); else g.moveTo(px, py);
      }
      g.strokeStyle = k === 0 ? T.ink : css(heatRGB(T, 0.6), 0.9);
      g.lineWidth = k === 0 ? 1 : 0.8;
      g.stroke();
      g.fillStyle = T.muted; g.textAlign = "left";
      g.fillText(num(row.t) ? clock(row.t) : "", ox + PW + 6, oy - 2);
    }
    // The frequency axis under the front row, and the band strip.
    g.fillStyle = T.muted; g.strokeStyle = T.rule; g.textAlign = "center";
    var tk = ticks(), lastX = -100;
    for (var i = 0; i < tk.length; i++) {
      var tx = L + fracOf(tk[i]) * PW;
      g.beginPath(); g.moveTo(tx, base0); g.lineTo(tx, base0 + 4); g.stroke();
      if (tx - lastX > 40) { g.fillText(tickText(tk[i]), tx, base0 + 15); lastX = tx; }
    }
    g.textAlign = "right"; g.fillText("MHz", L + PW, base0 + 28);
    bandStrip(g, T, L, base0 + 32, PW);
    peakLabels(g, T, lr, span);
    if (drag && drag.x1 !== undefined) {
      g.fillStyle = css(rgbOf(g, T.signal), 0.15);
      g.fillRect(Math.min(drag.x0, drag.x1), top - 10, Math.abs(drag.x1 - drag.x0), base0 - top + 10);
    }
    if (hover) {
      g.strokeStyle = T.signal; g.lineWidth = 1;
      g.beginPath(); g.moveTo(hover.x, hover.oy); g.lineTo(hover.x, hover.oy - RH); g.stroke();
    }
  }

  function bandStrip(g, T, x0, y, PW) {
    var lanes = [[], []];
    for (var i = 0; i < BANDS.length; i++) {
      var b = BANDS[i], lo = b[0] * 1e6, hi = b[1] * 1e6;
      if (hi < view.lo || lo > view.hi) continue;
      var a = x0 + Math.max(0, fracOf(Math.max(lo, view.lo))) * PW;
      var z = x0 + Math.min(1, fracOf(Math.min(hi, view.hi))) * PW;
      var lane = 0;
      for (var j = 0; j < lanes[0].length; j++) if (lanes[0][j][0] < z && lanes[0][j][1] > a) lane = 1;
      lanes[lane].push([a, z]);
      var ly = y + lane * 11;
      g.fillStyle = css(rgbOf(g, T.data), lane ? 0.10 : 0.16);
      g.fillRect(a, ly, Math.max(1, z - a), 10);
      g.strokeStyle = T.rule; g.strokeRect(a + 0.5, ly + 0.5, Math.max(1, z - a) - 1, 9);
      var label = b[2], w = g.measureText(label).width;
      if (z - a > w + 4) { g.fillStyle = T.ink; g.textAlign = "left"; g.fillText(label, a + 2, ly + 8.5); }
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
  function rowAt(y) {
    // The row whose ridge band (its baseline up to RH above it) holds
    // y, frontmost first; else the nearest baseline.
    for (var k = 0; k < geo.n; k++) {
      var oy = geo.base0 - k * geo.DY;
      if (y <= oy + 2 && y >= oy - geo.RH * 0.35) return k;
    }
    return 0;
  }
  function onMove(ev) {
    if (!geo || !doc) return;
    var r = ev.currentTarget.getBoundingClientRect(), x = ev.clientX - r.left, y = ev.clientY - r.top;
    if (drag) { drag.x1 = Math.max(geo.L, Math.min(geo.L + geo.PW, x)); draw(); return; }
    var k = rowAt(y), ox = geo.L + k * geo.DX, f = (x - ox) / geo.PW;
    var tip = $("spec-tip");
    if (f < 0 || f > 1) { hover = null; tip.hidden = true; draw(); return; }
    var hz = hzOf(f), row = rows[geo.n - 1 - k];
    var cols = Math.max(50, Math.floor(geo.PW)), c = Math.floor(f * cols);
    var a = Math.max(0, binOf(hzOf(c / cols))), b = Math.max(a, Math.min(doc.bins - 1, binOf(hzOf((c + 1) / cols)) - 1));
    var q = colMax(row.q, a, b), db = qDb(q);
    hover = { x: ox + f * geo.PW, oy: geo.base0 - k * geo.DY };
    clear(tip);
    tip.appendChild(el("div", "", mhz(hz) + (bandOf(hz) ? "  " + bandOf(hz) : "")));
    tip.appendChild(el("div", "", "level " + (db === null ? "below " + qOff() : db.toFixed(1)) + " dBFS" +
      (num(row.floor) && db !== null ? "  SNR " + (db - row.floor).toFixed(1) + " dB" : "")));
    tip.appendChild(el("div", "d-dim", "row " + (num(row.t) ? clock(row.t) : "-") + "  floor " +
      (num(row.floor) ? row.floor.toFixed(1) : "-") + " dBFS"));
    var near = nearestPeak(hz, (hzOf((c + 3) / cols) - hzOf((c - 2) / cols)));
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
      if (b - a > doc.bin_hz * 4) { view.lo = a; view.hi = b; preset(-1); }
    }
    draw();
    peakList();
  }
  function onLeave() { hover = null; drag = null; $("spec-tip").hidden = true; draw(); }

  // The preset in force is pressed; a drag-zoom presses none. Not kept:
  // a zoom is a look at one sweep, not a setting.
  function preset(k) {
    var bs = $("spec-zoom").getElementsByTagName("button");
    for (var i = 0; i < bs.length; i++) {
      var on = i === k;
      bs[i].className = on ? "on" : "go";
      bs[i].ariaPressed = on ? "true" : "false";
    }
  }
  function zoomTo(i) {
    if (!doc) return;
    var p = PRESETS[i];
    view.lo = p[1] ? Math.max(doc.f_lo, p[1]) : doc.f_lo;
    view.hi = p[2] ? Math.min(doc.f_hi, p[2]) : doc.f_hi;
    if (!(view.hi > view.lo)) { view.lo = doc.f_lo; view.hi = doc.f_hi; }
    preset(i);
    draw();
    peakList();
  }

  // ── the peak list: the canvas's words, for every peak in view ────
  function peakList() {
    var box = clear($("spec-peaks")), p = peaksInView();
    set("spec-peaks-count", doc ? p.length + " in view of " + (doc.peaks ? doc.peaks.length : 0) : "");
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
      s.why_not === "cooldown" ? "one run per cooldown (" + mmss(s.cooldown || 600) + ") so the shared receiver is not monopolised" :
      "a run is " + (s.why_not || "not possible");
  }

  function sweepMeta() {
    var m = clear($("spec-meta"));
    if (!doc) { m.appendChild(el("span", "d-dim", "no sweep yet: press Run, or start sloth-sdrsweep.service")); return; }
    m.appendChild(el("span", "", mhz(doc.f_lo, 1) + " to " + mhz(doc.f_hi, 0) + ", " + rows.length + " rows of " +
      doc.steps + " steps, " + when(doc.started) + " to " + clock(doc.ended) +
      (doc.complete === false ? " (stopped early)" : "")));
    m.appendChild(el("span", "d-dim", "  " + (doc.hardware || doc.driver || "") + (doc.serial ? " " + doc.serial : "") +
      ", antenna " + (doc.antenna || "-") + ", gain " + (doc.gain || "-") + ", " + (doc.sample_rate / 1e6) + " MS/s, " +
      (doc.nfft || "?") + "-point FFT, " + (doc.frames || "?") + " frames a step" +
      (doc.calibrated ? ", spurs calibrated" : ", no spur calibration")));
    set("spec-antenna", doc.antenna || "the configured antenna");
  }

  function poll(full) {
    var g = gen;
    getJSON("/api/spectrum" + (full ? "" : "?status=1")).then(function (j) {
      if (g !== gen) return;
      st = j;
      statusLine(j);
      var s = j.state + (j.running ? "r" : "") + (j.queued ? "q" : "");
      if (full) { take(j.sweep); sweepMeta(); draw(); peakList(); }
      else if (lastState && lastState !== s && !j.running && !j.queued) {
        /* The run the button queued has ended: its "queued" note is stale. */
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
    var z = $("spec-zoom");
    PRESETS.forEach(function (p, i) {
      var b = el("button", "go", p[0]);
      b.type = "button";
      b.addEventListener("click", function () { zoomTo(i); });
      z.appendChild(b);
    });
    preset(0);
    var lg = $("spec-log");
    lg.addEventListener("change", function () { view.log = lg.checked; draw(); });
    $("spec-topn").addEventListener("change", draw);
    $("spec-run").addEventListener("click", run);
    var cv = $("spec-plot");
    cv.addEventListener("mousemove", onMove);
    cv.addEventListener("mousedown", onDown);
    cv.addEventListener("mouseup", onUp);
    cv.addEventListener("mouseleave", onLeave);
    cv.addEventListener("dblclick", function () { zoomTo(0); });
    window.addEventListener("resize", function () { if (visible()) draw(); });
  }

  window.SlothSpectrum = {
    show: function () {
      wire();
      gen++;
      lastState = "";
      poll(true);
    },
    redraw: function () { if (visible()) draw(); }
  };
})();
