// slothweb: the amateur band charts on the Spectrum tab (owner
// 2026-11-18: "make spectrums for each ham band with common ham
// frequencies and local repeaters mapped"). window.SlothHam, one hook
// spectrum.js calls after each sweep it shows:
//   SlothHam.draw(c)   c.doc the sweep document, c.row its newest row
//                      (q, the quantised max-hold per bin), c.peaks its
//                      peaks, c.db(q) a level in dBFS, c.floor the
//                      row's floor, c.zoom(loHz, hiHz) the waterfall's
// One chart per United States amateur band inside the sweep: the band
// plan as coloured segments, the common frequencies as named marks,
// the operator's own marks (the local repeaters: GET
// /api/spectrum?marks=1, slothweb --spectrum-marks FILE) in the signal
// colour, and over them what the newest sweep row heard: its max-hold
// per bin as bars and its peaks as stems. A click zooms the waterfall
// to the band.
// The plan is the ARRL band plan and 47 CFR 97.301/97.305, simplified,
// for orientation and not a regulatory reference; the marks are
// conventions (calling frequencies, digital-mode dial frequencies),
// which no rule sets. The table is the United States'.
// The sweep's bins are 100 kHz or wider: an HF band is a handful of
// bars, and a mark is where a signal would be, never that one is.
// Every string shown is this file's or went through the server's own
// writer: textContent and fillText only, no markup sink.
(function () {
  "use strict";
  // Segment kinds: [key, name, colour token]. The palette's, no new one.
  var KINDS = [["cw", "CW, data", "--br-0"], ["ph", "phone", "--br-9"], ["ws", "weak signal", "--br-12"],
               ["bcn", "beacons", "--br-2"], ["fm", "FM simplex", "--br-3"], ["rin", "repeater in", "--br-4"],
               ["rout", "repeater out", "--br-14"], ["sat", "satellite", "--br-10"], ["dig", "digital", "--br-7"],
               ["atv", "ATV, wideband", "--br-15"], ["mix", "mixed, local option", "--br-6"]];
  // [name, lo MHz, hi MHz, segments [lo, hi, kind], marks [MHz, name]].
  var HAM = [
    ["160 m", 1.8, 2.0,
     [[1.8, 1.84, "cw"], [1.84, 2.0, "ph"]],
     [[1.81, "QRP CW"], [1.8366, "WSPR"], [1.84, "FT8"], [1.91, "QRP SSB"], [1.9, "AM"]]],
    ["80 m", 3.5, 4.0,
     [[3.5, 3.6, "cw"], [3.6, 4.0, "ph"]],
     [[3.56, "QRP CW"], [3.5686, "WSPR"], [3.573, "FT8"], [3.575, "FT4"], [3.578, "JS8"], [3.58, "PSK31"],
      [3.845, "SSTV"], [3.885, "AM"], [3.985, "QRP SSB"]]],
    ["60 m", 5.3305, 5.4065,
     [[5.3305, 5.3335, "mix"], [5.3465, 5.3495, "mix"], [5.357, 5.36, "mix"], [5.3715, 5.3745, "mix"],
      [5.4035, 5.4065, "mix"]],
     [[5.332, "ch 1"], [5.348, "ch 2"], [5.3585, "ch 3, FT8 5.357"], [5.373, "ch 4"], [5.405, "ch 5"]]],
    ["40 m", 7.0, 7.3,
     [[7.0, 7.125, "cw"], [7.125, 7.3, "ph"]],
     [[7.03, "QRP CW"], [7.0386, "WSPR"], [7.0475, "FT4"], [7.07, "PSK31"], [7.074, "FT8"], [7.078, "JS8"],
      [7.171, "SSTV"], [7.285, "QRP SSB"], [7.29, "AM"]]],
    ["30 m", 10.1, 10.15,
     [[10.1, 10.15, "cw"]],
     [[10.106, "QRP CW"], [10.13, "JS8"], [10.136, "FT8"], [10.1387, "WSPR"], [10.14, "FT4"], [10.142, "PSK31"]]],
    ["20 m", 14.0, 14.35,
     [[14.0, 14.15, "cw"], [14.15, 14.35, "ph"]],
     [[14.06, "QRP CW"], [14.07, "PSK31"], [14.074, "FT8"], [14.078, "JS8"], [14.08, "FT4"], [14.0956, "WSPR"],
      [14.1, "NCDXF beacons"], [14.23, "SSTV"], [14.285, "QRP SSB"], [14.286, "AM"], [14.3, "maritime net"]]],
    ["17 m", 18.068, 18.168,
     [[18.068, 18.11, "cw"], [18.11, 18.168, "ph"]],
     [[18.096, "QRP CW"], [18.1, "FT8"], [18.104, "FT4"], [18.1046, "WSPR"], [18.11, "NCDXF beacons"],
      [18.13, "QRP SSB"]]],
    ["15 m", 21.0, 21.45,
     [[21.0, 21.2, "cw"], [21.2, 21.45, "ph"]],
     [[21.06, "QRP CW"], [21.07, "PSK31"], [21.074, "FT8"], [21.0946, "WSPR"], [21.14, "FT4"],
      [21.15, "NCDXF beacons"], [21.34, "SSTV"], [21.385, "QRP SSB"]]],
    ["12 m", 24.89, 24.99,
     [[24.89, 24.93, "cw"], [24.93, 24.99, "ph"]],
     [[24.906, "QRP CW"], [24.915, "FT8"], [24.919, "FT4"], [24.9246, "WSPR"], [24.93, "NCDXF beacons"],
      [24.95, "QRP SSB"]]],
    ["10 m", 28.0, 29.7,
     [[28.0, 28.2, "cw"], [28.2, 28.3, "bcn"], [28.3, 29.0, "ph"], [29.0, 29.2, "mix"], [29.3, 29.51, "sat"],
      [29.52, 29.59, "rin"], [29.59, 29.61, "fm"], [29.62, 29.68, "rout"]],
     [[28.06, "QRP CW"], [28.074, "FT8"], [28.12, "PSK31"], [28.1246, "WSPR"], [28.18, "FT4"],
      [28.2, "NCDXF beacons"], [28.385, "QRP SSB"], [28.4, "SSB calling"], [28.68, "SSTV"], [29.0, "AM"],
      [29.6, "FM calling"]]],
    ["6 m", 50.0, 54.0,
     [[50.0, 50.1, "bcn"], [50.1, 50.3, "ws"], [50.3, 50.6, "mix"], [50.6, 50.8, "dig"], [50.8, 51.0, "mix"],
      [51.0, 51.1, "ws"], [51.12, 51.48, "rin"], [51.62, 51.98, "rout"], [52.0, 52.48, "rin"],
      [52.5, 52.98, "rout"], [53.0, 53.48, "rin"], [53.5, 53.98, "rout"]],
     [[50.09, "CW calling"], [50.11, "DX window"], [50.125, "SSB calling"], [50.26, "MSK144"], [50.293, "WSPR"],
      [50.313, "FT8"], [50.318, "FT4"], [50.4, "AM calling"], [52.525, "FM calling"]]],
    ["2 m", 144.0, 148.0,
     [[144.0, 144.1, "cw"], [144.1, 144.275, "ws"], [144.275, 144.3, "bcn"], [144.3, 144.5, "sat"],
      [144.5, 144.6, "mix"], [144.6, 144.9, "rin"], [144.9, 145.1, "dig"], [145.1, 145.2, "mix"],
      [145.2, 145.5, "rout"], [145.5, 145.8, "mix"], [145.8, 146.0, "sat"], [146.01, 146.37, "rin"],
      [146.4, 146.58, "fm"], [146.61, 147.39, "rout"], [147.42, 147.57, "fm"], [147.6, 147.99, "rin"]],
     [[144.1, "CW calling"], [144.15, "MSK144"], [144.174, "FT8"], [144.2, "SSB calling"], [144.39, "APRS"],
      [144.489, "WSPR"], [145.01, "packet"], [145.8, "ISS voice down"], [145.825, "ISS APRS"],
      [145.99, "ISS repeater up"], [146.52, "FM calling"], [146.58, "simplex"], [147.42, "simplex"]]],
    ["1.25 m", 222.0, 225.0,
     [[222.0, 222.15, "ws"], [222.15, 222.25, "mix"], [222.25, 223.38, "rin"], [223.4, 223.52, "fm"],
      [223.52, 223.64, "dig"], [223.64, 223.7, "mix"], [223.71, 223.85, "mix"], [223.85, 224.98, "rout"]],
     [[222.1, "SSB/CW calling"], [223.5, "FM calling"]]],
    ["70 cm", 420.0, 450.0,
     [[420.0, 432.0, "atv"], [432.0, 432.1, "cw"], [432.1, 432.3, "ws"], [432.3, 432.4, "bcn"],
      [432.4, 433.0, "ws"], [433.0, 435.0, "mix"], [435.0, 438.0, "sat"], [438.0, 442.0, "atv"],
      [442.0, 445.0, "rout"], [445.0, 447.0, "fm"], [447.0, 450.0, "rin"]],
     [[432.1, "SSB/CW calling"], [432.174, "FT8"], [437.8, "ISS repeater down"], [446.0, "FM calling"],
      [446.5, "simplex"]]],
    ["33 cm", 902.0, 928.0,
     [[902.0, 903.0, "ws"], [903.0, 906.0, "dig"], [906.0, 909.0, "rin"], [909.0, 915.0, "atv"],
      [915.0, 918.0, "dig"], [918.0, 921.0, "rout"], [921.0, 927.0, "atv"], [927.0, 928.0, "fm"]],
     [[902.1, "SSB/CW calling"], [903.1, "alt calling"], [927.5, "FM calling"]]],
    ["23 cm", 1240.0, 1300.0,
     [[1240.0, 1246.0, "atv"], [1246.0, 1252.0, "dig"], [1252.0, 1258.0, "atv"], [1258.0, 1260.0, "mix"],
      [1260.0, 1270.0, "sat"], [1270.0, 1276.0, "rin"], [1276.0, 1282.0, "atv"], [1282.0, 1288.0, "rout"],
      [1288.0, 1294.0, "mix"], [1294.0, 1295.0, "fm"], [1295.0, 1297.0, "ws"], [1297.0, 1300.0, "dig"]],
     [[1294.5, "FM calling"], [1296.1, "SSB/CW calling"]]]
  ];

  var ISO = window.SlothIso;
  var local = [], localState = "", asked = false, last = null, built = false;

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return v && v.trim() ? v.trim() : fallback;
  }
  function kindOf(key) { for (var i = 0; i < KINDS.length; i++) if (KINDS[i][0] === key) return KINDS[i]; return null; }
  function fmt(m) { return String(+m.toFixed(4)); }

  // The operator's marks, asked for once a page: a list changes with a
  // restart's worth of rarity, and a refusal is said once.
  function ask() {
    if (asked) return;
    asked = true;
    fetch("/api/spectrum?marks=1", { credentials: "same-origin", cache: "no-store" }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    }).then(function (j) {
      var m = j && Array.isArray(j.marks) ? j.marks : [], out = [];
      for (var i = 0; i < m.length; i++)
        if (m[i] && num(m[i].f_hz) && typeof m[i].label === "string") out.push([m[i].f_hz / 1e6, m[i].label]);
      local = out;
      localState = !j || !j.configured ? "no local marks file (slothweb --spectrum-marks)" :
        j.error ? "local marks: " + String(j.error) :
        out.length + " local mark" + (out.length === 1 ? "" : "s") + (num(j.skipped) && j.skipped ? ", " + j.skipped + " line" + (j.skipped === 1 ? "" : "s") + " skipped" : "");
      if (last) draw(last);
    }).catch(function (e) {
      localState = "local marks unavailable: " + (e && e.message ? e.message : "error");
      if (last) draw(last);
    });
  }

  function build() {
    if (built) return;
    built = true;
    var grid = $("ham-grid");
    HAM.forEach(function (b, i) {
      var box = el("div", "ham-band"), hd = el("div", "ham-hd");
      hd.appendChild(el("b", "", b[0]));
      hd.appendChild(el("span", "", fmt(b[1]) + " to " + fmt(b[2]) + " MHz"));
      hd.appendChild(el("span", "ham-st", ""));
      var cv = el("canvas", "ham-cv");
      cv.ariaLabel = b[0] + " amateur band, " + fmt(b[1]) + " to " + fmt(b[2]) + " MHz: band plan, common frequencies, " +
        "local marks, and the newest sweep's level and peaks; click to zoom the waterfall to it";
      cv.addEventListener("click", function () { if (last && last.zoom) last.zoom(b[1] * 1e6, b[2] * 1e6); });
      cv.addEventListener("mousemove", function (ev) { hover(cv, i, ev); });
      box.appendChild(hd);
      box.appendChild(cv);
      grid.appendChild(box);
    });
    var key = $("ham-key");
    KINDS.forEach(function (k) {
      var it = el("span", "ham-k"), sw = el("canvas", "ham-sw");
      sw.width = 10; sw.height = 10;
      it.appendChild(sw);
      it.appendChild(el("span", "", k[1]));
      key.appendChild(it);
    });
  }

  // The marks of band b: the table's, then the operator's inside it.
  function marksOf(b) {
    var out = [], i;
    for (i = 0; i < b[4].length; i++) out.push([b[4][i][0], b[4][i][1], false]);
    for (i = 0; i < local.length; i++)
      if (local[i][0] >= b[1] && local[i][0] <= b[2]) out.push([local[i][0], local[i][1], true]);
    out.sort(function (p, q) { return p[0] - q[0]; });
    return out;
  }

  // What is under the pointer, as the canvas's hover note.
  function hover(cv, i, ev) {
    var b = HAM[i], r = cv.getBoundingClientRect(), L = 34, PW = r.width - L - 8;
    var m = b[1] + (ev.clientX - r.left - L) / PW * (b[2] - b[1]);
    if (m < b[1] || m > b[2]) { cv.title = ""; return; }
    var t = fmt(m) + " MHz", s, k, mk = marksOf(b), tol = (b[2] - b[1]) * 5 / PW, near = [];
    for (k = 0; k < b[3].length; k++) {
      s = b[3][k];
      if (m >= s[0] && m <= s[1] && kindOf(s[2])) { t += "  " + kindOf(s[2])[1]; break; }
    }
    for (k = 0; k < mk.length; k++) if (Math.abs(mk[k][0] - m) <= tol) near.push(fmt(mk[k][0]) + " " + mk[k][1]);
    if (near.length) t += "\n" + near.join("\n");
    cv.title = t;
  }

  var ROWS = 4, ROW_H = 11, PLOT_H = 56, PLAN_H = 12, AXIS_H = 16;
  function one(cv, b, c, T) {
    var dpr = window.devicePixelRatio || 1, W = cv.clientWidth, Hh = ROWS * ROW_H + 6 + PLOT_H + PLAN_H + AXIS_H;
    if (W < 60) return [0, 0];
    cv.width = Math.round(W * dpr); cv.height = Math.round(Hh * dpr);
    var g = cv.getContext("2d");
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, W, Hh);
    g.font = "10px " + cssVar("--font-mono", "monospace");
    var L = 34, PW = W - L - 8, top = ROWS * ROW_H + 6, base = top + PLOT_H, lo = b[1], hi = b[2], i;
    function x(m) { return L + (m - lo) / (hi - lo) * PW; }
    // The plan.
    for (i = 0; i < b[3].length; i++) {
      var s = b[3][i], k = kindOf(s[2]);
      if (!k) continue;
      var col = cssVar(k[2], T.data), a = x(s[0]), w = Math.max(1.5, x(s[1]) - a);
      g.fillStyle = ISO.css(ISO.rgbOf(g, col), 0.45); g.fillRect(a, base + 1, w, PLAN_H - 2);
      g.fillStyle = col; g.fillRect(a, base + 1, Math.min(w, 1.5), PLAN_H - 2);
      var tw = g.measureText(k[1]).width;
      if (w > tw + 6) { g.fillStyle = T.ink; g.textAlign = "left"; g.fillText(k[1], a + 4, base + PLAN_H - 3); }
    }
    // The axis: the band's edges and round steps between.
    g.strokeStyle = T.rule; g.fillStyle = T.muted; g.textAlign = "center";
    var span = hi - lo, raw = span / Math.max(2, Math.floor(PW / 70));
    var mag = Math.pow(10, Math.floor(Math.log(raw) / Math.LN10)), step = mag;
    if (raw / mag > 5) step = 10 * mag; else if (raw / mag > 2) step = 5 * mag; else if (raw / mag > 1) step = 2 * mag;
    for (var t = Math.ceil(lo / step - 1e-9) * step; t <= hi + 1e-9; t += step) {
      g.beginPath(); g.moveTo(x(t), base + PLAN_H); g.lineTo(x(t), base + PLAN_H + 3); g.stroke();
      g.fillText(fmt(t), Math.max(L + 12, Math.min(L + PW - 12, x(t))), base + PLAN_H + 13);
    }
    g.beginPath(); g.moveTo(L, base + 0.5); g.lineTo(L + PW, base + 0.5); g.stroke();
    // The newest row: its max-hold per bin, floor to level.
    var npk = 0, heard = false;
    if (c && c.doc && c.row && num(c.doc.f_lo) && num(c.doc.bin_hz) && c.doc.bin_hz > 0) {
      var d = c.doc, q = c.row.q, fl = num(c.floor) ? c.floor : -110;
      var b0 = Math.max(0, Math.floor((lo * 1e6 - d.f_lo) / d.bin_hz));
      var b1 = Math.min(d.bins - 1, Math.floor((hi * 1e6 - 1 - d.f_lo) / d.bin_hz));
      var mx = fl + 20, j, db;
      for (j = b0; j <= b1; j++) { db = c.db(q[j]); if (db !== null && db > mx) mx = db; }
      for (j = 0; j < c.peaks.length; j++) {
        var p = c.peaks[j];
        if (p && num(p.freq_hz) && p.freq_hz >= lo * 1e6 && p.freq_hz <= hi * 1e6 && num(p.dbfs) && p.dbfs > mx) mx = p.dbfs;
      }
      var y0 = fl - 3, y1 = mx + 2;
      var yy = function (v) { return base - Math.max(0, Math.min(1, (v - y0) / (y1 - y0))) * PLOT_H; };
      if (b1 >= b0 && hi * 1e6 > d.f_lo && lo * 1e6 < d.f_hi) {
        heard = true;
        g.fillStyle = ISO.css(ISO.rgbOf(g, T.data), 0.35);
        for (j = b0; j <= b1; j++) {
          db = c.db(q[j]);
          if (db === null) continue;
          var xa = Math.max(L, x((d.f_lo + j * d.bin_hz) / 1e6)), xb = Math.min(L + PW, x((d.f_lo + (j + 1) * d.bin_hz) / 1e6));
          g.fillRect(xa, yy(db), Math.max(1, xb - xa - 0.5), base - yy(db));
        }
        g.fillStyle = T.muted; g.textAlign = "right";
        g.fillText(String(Math.round(y1)), L - 4, top + 8);
        g.fillText(String(Math.round(y0)), L - 4, base);
        g.strokeStyle = T.signal;
        for (j = 0; j < c.peaks.length; j++) {
          p = c.peaks[j];
          if (!p || !num(p.freq_hz) || p.freq_hz < lo * 1e6 || p.freq_hz > hi * 1e6 || p.note === "internal") continue;
          npk++;
          var px = x(p.freq_hz / 1e6);
          g.beginPath(); g.moveTo(px + 0.5, base); g.lineTo(px + 0.5, yy(num(p.dbfs) ? p.dbfs : y0)); g.stroke();
        }
      }
    }
    if (!heard) { g.fillStyle = T.faint; g.textAlign = "left"; g.fillText("outside the sweep", L + 4, top + 12); }
    // The marks: a hairline through the plot and a name above it where
    // one fits; the rest are the hover note's.
    var mk = marksOf(b), used = [], nloc = 0;
    mk.sort(function (p0, p1) { return (p1[2] ? 1 : 0) - (p0[2] ? 1 : 0) || p0[0] - p1[0]; });
    for (i = 0; i < mk.length; i++) {
      var mx0 = x(mk[i][0]), text = mk[i][1].length > 22 ? mk[i][1].slice(0, 21) + "…" : mk[i][1];
      var mw = g.measureText(text).width + 6, row = -1, r, u, ok;
      if (mk[i][2]) nloc++;
      var tx = Math.max(L + mw / 2, Math.min(L + PW - mw / 2, mx0));
      for (r = ROWS - 1; r >= 0 && row < 0; r--) {
        ok = true;
        for (u = 0; u < used.length; u++) if (used[u][2] === r && tx - mw / 2 < used[u][1] && tx + mw / 2 > used[u][0]) ok = false;
        if (ok) row = r;
      }
      g.strokeStyle = mk[i][2] ? T.signal : T.faint;
      g.setLineDash(mk[i][2] ? [] : [2, 3]);
      g.beginPath(); g.moveTo(mx0 + 0.5, row < 0 ? top : row * ROW_H + ROW_H); g.lineTo(mx0 + 0.5, base); g.stroke();
      g.setLineDash([]);
      if (row < 0) continue;
      used.push([tx - mw / 2, tx + mw / 2, row]);
      g.fillStyle = mk[i][2] ? T.signal : T.ink; g.textAlign = "center";
      g.fillText(text, tx, row * ROW_H + 9);
    }
    return [npk, nloc];
  }

  function draw(c) {
    last = c;
    var grid = $("ham-grid");
    if (!grid) return;
    build();
    ask();
    var probe = document.createElement("canvas").getContext("2d"), T = ISO.theme(probe);
    var boxes = grid.children, heard = 0, i;
    for (i = 0; i < HAM.length && i < boxes.length; i++) {
      var n = one(boxes[i].lastChild, HAM[i], c, T), st = boxes[i].firstChild.lastChild;
      st.textContent = (n[0] ? n[0] + " peak" + (n[0] === 1 ? "" : "s") : "") + (n[0] && n[1] ? ", " : "") +
        (n[1] ? n[1] + " local" : "");
      if (n[0]) heard++;
    }
    var sw = $("ham-key").getElementsByTagName("canvas");
    for (i = 0; i < sw.length && i < KINDS.length; i++) {
      var g = sw[i].getContext("2d");
      g.clearRect(0, 0, 10, 10);
      g.fillStyle = cssVar(KINDS[i][2], T.data); g.fillRect(0, 0, 10, 10);
    }
    var note = $("ham-note");
    if (note) note.textContent = HAM.length + " bands, peaks in " + heard + (localState ? "; " + localState : "");
  }

  window.SlothHam = { draw: draw, HAM: HAM, KINDS: KINDS, marksOf: marksOf };
})();
