// The glyph layer (docs/web-visual-spec.md §5; slice V0: G1, G5, G6;
// slice V1: G1's words, the episode shade, shared scales, G4; slice V2:
// G2, its words, the new mark; slice V3: G3, G7; slice V4: G8 and the
// Flows matrix).
//
// Every glyph is two halves. The first maps data and a size to a list
// of marks, each `[kind, x, y, w, h, token]` in CSS pixels with a
// colour *token* and no canvas, no DOM and no theme (a word the glyph
// writes is a seventh member, its text, painted in that token at the
// mark's h as its size in pixels): it is a pure
// function of its arguments, so a test can read what a glyph says
// without a browser. The second (paint) draws a mark list. The rules
// the two halves follow are R1 to R12 in web/README.md.
//
// The mark lists are ported line for line into C in
// web/tests/test_glyph.c, which pins the JS below verbatim out of the
// served page, so a change to either side fails `make web-test`. That
// is the same mechanism test_tui_colors.c uses for the TUI's colours,
// and it is why `make web-test` needs no node and no other dependency
// (owner ruling 2 of 2026-10-26).
var glyph = (function () {
  function gnum(v) { return typeof v === "number" && isFinite(v); }

  // R6: fewer than five points draw dots, never a line.
  var DOTS_BELOW = 5;
  // R5: a gap of more than this many steps breaks the line.
  var GAP_STEPS = 2.5;
  // R4: data covering less than this share of the window shrinks it.
  var WINDOW_SHARE = 0.1;

  // draw_sparkline_at() (src/views/dashboard_primitives.c), as app.js
  // ports it: level 0 is dim, 1-2 normal, 3-4 heat mid, 5-6 heat high,
  // 7-8 peak. Owner ruling 1 of 2026-10-26 keeps G1's line graded this
  // way for parity with the TUI; R1's one ink holds for every other
  // glyph, and out of band is still said by the band and the last dot.
  function level(v, max) {
    if (!(v > 0) || !(max > 0)) return 0;
    var l = Math.floor(v / max * 8 + 0.5);
    return l < 1 ? 1 : l > 8 ? 8 : l;
  }
  function lineToken(l) {
    return l === 0 ? "--tui-dim" : l <= 2 ? "--tui-normal" :
           l <= 4 ? "--heat-1" : l <= 6 ? "--heat-2" : "--heat-3";
  }
  // tui_heat's thresholds, as app.js heat() ports them.
  function heatToken(f) {
    return f < 0.15 ? "--heat-0" : f < 0.40 ? "--heat-1" :
           f < 0.70 ? "--heat-2" : "--heat-3";
  }

  // A window's length in the words a caption uses. A whole day reads
  // "24 h", not "1 d", because R4's example says "6 min of 24 h".
  function dur(s) {
    s = Math.round(s);
    if (s < 60) return s + " s";
    if (s < 3600) return Math.round(s / 60) + " min";
    if (s <= 86400) return Math.round(s / 3600) + " h";
    return Math.round(s / 86400) + " d";
  }

  // R4. The window a glyph draws, which is the one it was asked for
  // unless the data covers less than a tenth of it: then it is the
  // data's own span, and `text` is what the caption must say.
  function win(pts, from, to) {
    var span = to - from, o = { from: from, to: to, shrunk: false, text: "" };
    if (!pts || pts.length < 2 || !(span > 0)) return o;
    var cover = pts[pts.length - 1][0] - pts[0][0];
    if (!(cover > 0) || cover >= span * WINDOW_SHARE) return o;
    o.from = pts[0][0];
    o.to = pts[pts.length - 1][0];
    o.shrunk = true;
    o.text = dur(cover) + " of " + dur(span);
    return o;
  }

  // R11. A glyph's y-range grows to hold the data and the band and
  // never shrinks on a refresh, so a reader can look away and back.
  // `prev` is the range the glyph last drew, or null.
  function scale(pts, band, prev) {
    var lo = 0, hi = 0, i, b;
    for (i = 0; pts && i < pts.length; i++) {
      if (pts[i][1] > hi) hi = pts[i][1];
      if (pts[i][1] < lo) lo = pts[i][1];
      b = band && band[i];
      if (b) { if (b[1] > hi) hi = b[1]; if (b[0] < lo) lo = b[0]; }
    }
    if (prev) {
      if (prev[0] < lo) lo = prev[0];
      if (prev[1] > hi) hi = prev[1];
    }
    if (!(hi > lo)) hi = lo + 1;
    return [lo, hi];
  }

  // R9. The one --muted line under every panel: source, window, tier,
  // scale, n, and then the state when the glyph is not drawing data
  // ("warming", "no data", or R4's shrunk window).
  function caption(c) {
    var p = [];
    if (c.source) p.push(c.source);
    if (c.window) p.push(c.window);
    if (c.tier) p.push(c.tier);
    if (c.scale) p.push(c.scale);
    p.push("n=" + (gnum(c.n) ? Math.round(c.n) : 0));
    if (c.state) p.push(c.state);
    return p.join(", ");
  }

  // R5: the empty state. A --faint dash across the glyph's middle and
  // nothing else, so "no data" cannot be read as a flat line.
  function dash(w, h) { return ["dash", w * 0.35, h / 2, w * 0.3, 1, "--faint"]; }

  // G1, the band sparkline. pts are [t, v] oldest first; band is the
  // same length, each [lo, hi, mean, sd] or null where the cell is
  // warming, or null for no band at all. opt: {w, h, from, to, step,
  // sens, scale, shade} — shade is an anomaly episode's [first, last]
  // (F13), drawn under everything else and clipped to the window.
  function g1(pts, band, opt) {
    var m = [], w = opt.w, h = opt.h, i, b;
    if (!pts || !pts.length) { m.push(dash(w, h)); return m; }
    var step = opt.step > 0 ? opt.step : 1;
    var from = opt.from, to = opt.to;
    var sc = scale(pts, band, opt.scale || null), lo = sc[0], hi = sc[1];
    var X = function (t) { return to > from ? (t - from) / (to - from) * w : 0; };
    var Y = function (v) { return h - (v - lo) / (hi - lo) * h; };
    var sh = opt.shade;
    if (sh && gnum(sh[0]) && gnum(sh[1]) && to > from) {
      var sa = X(Math.max(sh[0], from)), sb = X(Math.min(sh[1] + step, to));
      if (sb > sa) m.push(["shade", sa, 0, Math.max(1, sb - sa), h, "--signal"]);
    }
    var any = false;
    for (i = 0; band && i < band.length; i++) if (band[i]) any = true;
    for (i = 0; any && i < pts.length; i++) {
      b = band[i];
      if (!b) continue;
      var bx = X(pts[i][0]);
      var bw = Math.min(Math.max(1, X(pts[i][0] + step) - bx), Math.max(0, w - bx));
      if (bw > 0) m.push(["band", bx, Y(b[1]), bw, Y(b[0]) - Y(b[1]), "--data"]);
    }
    var gap = step * GAP_STEPS, dots = pts.length < DOTS_BELOW, max = 0;
    for (i = 0; i < pts.length; i++) if (pts[i][1] > max) max = pts[i][1];
    for (i = 1; i < pts.length; i++) {
      var xa = X(pts[i - 1][0]), xb = X(pts[i][0]);
      if (pts[i][0] - pts[i - 1][0] > gap) {
        m.push(["gap", xa, 0, xb - xa, h, "--faint"]);
        continue;
      }
      if (dots) continue;
      m.push(["line", xa, Y(pts[i - 1][1]), xb - xa, Y(pts[i][1]) - Y(pts[i - 1][1]),
              lineToken(level(pts[i][1], max))]);
    }
    if (dots)
      for (i = 0; i < pts.length - 1; i++)
        m.push(["dot", X(pts[i][0]), Y(pts[i][1]), 1.5, 1.5, "--tui-normal"]);
    // R7: min and max dots only where there is no band to compare to.
    if (!any) {
      var xi = 0, ni = 0;
      for (i = 1; i < pts.length; i++) {
        if (pts[i][1] > pts[xi][1]) xi = i;
        if (pts[i][1] < pts[ni][1]) ni = i;
      }
      m.push(["max", X(pts[xi][0]), Y(pts[xi][1]), 1.5, 1.5, "--faint"]);
      if (ni !== xi) m.push(["min", X(pts[ni][0]), Y(pts[ni][1]), 1.5, 1.5, "--faint"]);
    }
    // R7: the last value is always marked. Out of band it takes the
    // heat ramp, by how far out it is, as the band chart already does.
    var k = pts.length - 1, lb = any ? band[k] : null, tok = "--ink";
    if (lb && lb[3] > 0 && (pts[k][1] > lb[1] || pts[k][1] < lb[0])) {
      var sens = opt.sens > 0 ? opt.sens : 2;
      var z = Math.abs(pts[k][1] - lb[2]) / lb[3];
      tok = heatToken(Math.min(1, (z - sens) / 4 + 0.15));
    }
    m.push(["last", X(pts[k][0]), Y(pts[k][1]), 2.5, 2.5, tok]);
    return m;
  }

  // G1's words (§5): the direction since the previous bucket, one of
  // the three arrows, or "" when there is no previous bucket to say it
  // against. A gap between the two is still a direction: the words say
  // where the value went, the line says how.
  function trend(pts) {
    if (!pts || pts.length < 2) return "";
    var a = pts[pts.length - 2][1], b = pts[pts.length - 1][1];
    return b > a ? "\u2191" : b < a ? "\u2193" : "\u2192";
  }

  // R3 and F6: small multiples share one y-scale, so a cell's height
  // means the same in every cell. sets are [{pts, band}]; prev is the
  // range the stack last drew (R11: grown, never shrunk).
  function shared(sets, prev) {
    var r = prev ? [prev[0], prev[1]] : null;
    for (var i = 0; sets && i < sets.length; i++) r = scale(sets[i].pts, sets[i].band, r);
    return r || [0, 1];
  }

  // F6's sort: by |z| when any row has a baseline to be scored against,
  // the rows without one after them by value; by value when none has.
  // rows are [{cur, z}], z a number or null; the answer is a new array
  // and the word the caption names the sort by.
  function order(rows) {
    var out = (rows || []).slice(), byz = false, i;
    for (i = 0; i < out.length; i++) if (gnum(out[i].z)) byz = true;
    out.sort(function (a, b) {
      if (byz) {
        var za = gnum(a.z), zb = gnum(b.z);
        if (za !== zb) return za ? -1 : 1;
        if (za && Math.abs(b.z) !== Math.abs(a.z)) return Math.abs(b.z) - Math.abs(a.z);
      }
      return (gnum(b.cur) ? b.cur : 0) - (gnum(a.cur) ? a.cur : 0);
    });
    return { rows: out, by: byz ? "|z|" : "value" };
  }

  // G4, the hour-of-week grid (F3). cells are 168 [mean, sd, n] from
  // Monday 00:00; a cell with n under warm is warming. opt: {w, h, x0,
  // y0, warm, now} — x0 and y0 leave room for the labels, now is the
  // current cell or -1. A fed cell is the heat ramp by its mean against
  // the largest fed mean; a warming cell is --rule and nothing else
  // (R8: no hatch). When every cell is warming the grid draws only the
  // now outline, and the caption says the rest (g4Stats).
  function g4(cells, opt) {
    var m = [], w = opt.w, h = opt.h, x0 = opt.x0 || 0, y0 = opt.y0 || 0, i;
    var cw = (w - x0) / 24, ch = (h - y0) / 7, st = g4Stats(cells, opt.warm);
    for (i = 0; st.fed && i < 168; i++) {
      var c = cells && cells[i], x = x0 + cw * (i % 24), y = y0 + ch * Math.floor(i / 24);
      if (c && c[2] >= st.warm)
        m.push(["cell", x + 1, y + 1, cw - 2, ch - 2,
                heatToken(st.max > 0 ? c[0] / st.max : 0)]);
      else m.push(["warm", x + 1, y + 1, cw - 2, ch - 2, "--rule"]);
    }
    var nc = opt.now;
    if (gnum(nc) && nc >= 0 && nc < 168)
      m.push(["outline", x0 + cw * (nc % 24), y0 + ch * Math.floor(nc / 24), cw, ch, "--signal"]);
    return m;
  }
  // G4's caption facts: the warming count, the largest fed mean (the
  // top of the ramp, printed), and the samples behind the fed cells.
  function g4Stats(cells, warm) {
    var o = { warm: gnum(warm) ? warm : 3, warming: 0, fed: 0, max: 0, n: 0 };
    for (var i = 0; i < 168; i++) {
      var c = cells && cells[i];
      if (!c || !(c[2] >= o.warm)) { o.warming++; continue; }
      o.fed++;
      o.n += c[2];
      if (c[0] > o.max) o.max = c[0];
    }
    return o;
  }

  // The server's 36 hex digits as n cells, cell 0 the oldest, its bit
  // the high bit of the first digit (web/README.md, presence_cells).
  function cellsFromHex(hex, n) {
    if (typeof hex !== "string" || !/^[0-9a-f]{36}$/.test(hex)) return [];
    n = gnum(n) && n >= 1 && n <= 144 ? Math.floor(n) : 144;
    var out = [];
    for (var i = 0; i < n; i++)
      out.push((parseInt(hex.charAt(i >> 2), 16) & (8 >> (i & 3))) ? 1 : 0);
    return out;
  }

  // G5, the binary presence strip. cells is an array, oldest first: 1
  // present, 0 absent, -1 an interval nothing was observed in (a gap,
  // R5). opt: {w, h, first, ground} — first is the index of the
  // first-seen cell, or -1 when the device was first seen before the
  // window; ground is the token an absent cell shows, for a strip that
  // sits on a panel but reads against the page's own ground.
  function g5(cells, opt) {
    var m = [], w = opt.w, h = opt.h, n = cells ? cells.length : 0, i;
    if (opt.ground) m.push(["ground", 0, 0, w, h, opt.ground]);
    if (!n) { m.push(dash(w, h)); return m; }
    var cw = w / n;
    for (i = 0; i < n; i++) {
      var x = Math.floor(i * cw), cwi = Math.max(1, Math.ceil(cw));
      if (cells[i] < 0) m.push(["gap", x, 0, cwi, h, "--faint"]);
      else if (cells[i] > 0) m.push(["cell", x, 0, cwi, h, "--tui-normal"]);
    }
    if (gnum(opt.first) && opt.first >= 0 && opt.first < n)
      m.push(["first", Math.floor(opt.first * cw), 0, Math.max(1, Math.ceil(cw)), h,
              "--signal"]);
    // An anomaly episode underlines the cells it covers, 1 px, so the
    // strip says when the device was here and when it was odd without
    // either reading changing the other (R1: colour for out of band).
    var ep = opt.episodes || [];
    for (i = 0; i < ep.length; i++) {
      var a = ep[i][0] < 0 ? 0 : ep[i][0], b = ep[i][1] > n - 1 ? n - 1 : ep[i][1];
      if (b < a) continue;
      m.push(["anom", Math.floor(a * cw), h - 1,
              Math.max(1, Math.ceil((b - a + 1) * cw)), 1, "--heat-2"]);
    }
    return m;
  }

  // G5's ruler (F10), drawn once per table rather than per row: a
  // --faint tick at each local midnight in the window and a --signal
  // tick at now. opt: {w, h, from, to, offset} — offset is the local
  // zone's offset from UTC in seconds, as /api/baseline reports it.
  function g5Ruler(opt) {
    var m = [], w = opt.w, h = opt.h, from = opt.from, to = opt.to;
    if (!(to > from)) return m;
    var off = gnum(opt.offset) ? opt.offset : 0;
    var first = Math.ceil((from + off) / 86400) * 86400 - off;
    for (var t = first; t <= to; t += 86400)
      m.push(["tick", (t - from) / (to - from) * w, 0, 1, h, "--faint"]);
    m.push(["now", w - 1, 0, 1, h, "--signal"]);
    return m;
  }

  // G2, the range sparkline (RSSI). pts are [t, dBm] oldest first.
  // opt: {w, h, from, to, step, whisker} — whisker is the [lo, hi] at
  // the last value (the beacon's 60 s range, or the last cell's), or
  // null. The scale is fixed, -95 to -20 dBm on every G2 on the page
  // (R3), so a line near the top is a near emitter in every row; a
  // reading past it is drawn at the edge and counted by g2Clamped(). A
  // --faint rule at -67 dBm, a field rule of thumb for good coverage
  // and not a standard (owner ruling 3), is the one reference. One ink
  // (R1): only G1's line is graded (ruling 1). One sample is the dot
  // alone, and the number beside it says the rest (§5 G2's states).
  var RSSI_LO = -95, RSSI_HI = -20, RSSI_REF = -67;
  function g2Y(v, h) {
    var c = v < RSSI_LO ? RSSI_LO : v > RSSI_HI ? RSSI_HI : v;
    return h - (c - RSSI_LO) / (RSSI_HI - RSSI_LO) * h;
  }
  function g2(pts, opt) {
    var m = [], w = opt.w, h = opt.h, i;
    if (!pts || !pts.length) { m.push(dash(w, h)); return m; }
    var step = opt.step > 0 ? opt.step : 1, from = opt.from, to = opt.to;
    var X = function (t) { return to > from ? (t - from) / (to - from) * w : w; };
    var k = pts.length - 1;
    if (!k) { m.push(["last", X(pts[0][0]), g2Y(pts[0][1], h), 2.5, 2.5, "--ink"]); return m; }
    m.push(["ref", 0, g2Y(RSSI_REF, h), w, 1, "--faint"]);
    var gap = step * GAP_STEPS, dots = pts.length < DOTS_BELOW;
    for (i = 1; i < pts.length; i++) {
      var xa = X(pts[i - 1][0]), xb = X(pts[i][0]);
      if (pts[i][0] - pts[i - 1][0] > gap) {
        m.push(["gap", xa, 0, xb - xa, h, "--faint"]);
        continue;
      }
      if (dots) continue;
      m.push(["line", xa, g2Y(pts[i - 1][1], h), xb - xa,
              g2Y(pts[i][1], h) - g2Y(pts[i - 1][1], h), "--tui-normal"]);
    }
    if (dots)
      for (i = 0; i < k; i++)
        m.push(["dot", X(pts[i][0]), g2Y(pts[i][1], h), 1.5, 1.5, "--tui-normal"]);
    var wk = opt.whisker;
    if (wk && gnum(wk[0]) && gnum(wk[1]) && wk[1] >= wk[0])
      m.push(["whisker", X(pts[k][0]), g2Y(wk[1], h), 1,
              Math.max(1, g2Y(wk[0], h) - g2Y(wk[1], h)), "--tui-normal"]);
    m.push(["last", X(pts[k][0]), g2Y(pts[k][1], h), 2.5, 2.5, "--ink"]);
    return m;
  }
  // §9: a reading off the fixed scale is clamped, and said.
  function g2Clamped(pts) {
    var n = 0;
    for (var i = 0; pts && i < pts.length; i++)
      if (pts[i][1] > RSSI_HI || pts[i][1] < RSSI_LO) n++;
    return n;
  }
  // G2's words agree with sloth's own distance estimate
  // (src/rf_distance.c) and fit no slope of their own: the number is
  // bold when sloth's trend says approaching, and after it come sloth's
  // band and trend glyph as the TUI's distance cell prints them
  // (rf_band_short, rf_trend_glyph). band and trend are the row's "rf"
  // words (web/src/web_rf.h), or null.
  var BAND_SHORT = { immediate: "imm", near: "near", room: "room", building: "bldg", far: "far" };
  var TREND_GLYPH = { approaching: "\u2198", steady: "\u2192", leaving: "\u2197" };
  function g2Words(last, band, trend) {
    var own = Object.prototype.hasOwnProperty;
    var b = typeof band === "string" && own.call(BAND_SHORT, band) ? BAND_SHORT[band] : "";
    var g = typeof trend === "string" && own.call(TREND_GLYPH, trend) ? TREND_GLYPH[trend] : "";
    return { text: gnum(last) ? String(Math.round(last)) : "-",
             bold: trend === "approaching", near: b && g ? b + " " + g : b || g };
  }

  // F15: new is first seen inside the window the row is shown against,
  // and G5's first-seen cell is the cell of the strip it falls in (-1
  // when it is before the strip, or after it).
  function isNew(first, from) { return gnum(first) && gnum(from) && first >= from; }
  function firstCell(first, from, cellS, n) {
    if (!isNew(first, from) || !(cellS > 0)) return -1;
    var c = Math.floor((first - from) / cellS);
    return c < n ? c : -1;
  }

  // G6, the bullet and the count bar. v is the measure. opt: {w, h,
  // max, ranges, threshold, count} — ranges are the qualitative band
  // edges of a bounded score, threshold the value the rule fires at,
  // count true for the bar form of a count in a column.
  function g6(v, opt) {
    var m = [], w = opt.w, h = opt.h, i;
    if (!gnum(v)) { m.push(dash(w, h)); return m; }
    var max = opt.max > 0 ? opt.max : 1;
    var r = (!opt.count && opt.ranges) || [];
    for (i = 0; i < r.length; i++) {
      var xa = i ? w * Math.min(1, r[i - 1] / max) : 0;
      var xb = w * Math.min(1, r[i] / max);
      if (xb > xa) m.push(["range", xa, 0, xb - xa, h, i ? "--rule" : "--faint"]);
    }
    var hot = gnum(opt.threshold) && v >= opt.threshold;
    m.push(["bar", 0, h * 0.25, w * Math.max(0, Math.min(1, v / max)), h * 0.5,
            opt.count ? "--rule" : hot ? "--sev-warn" : "--ink"]);
    if (!opt.count && gnum(opt.threshold) && opt.threshold > 0)
      m.push(["tick", w * Math.min(1, opt.threshold / max), 0, 1, h, "--signal"]);
    return m;
  }

  // G3, the horizon strip (F8). v are a channel's columns oldest
  // first, each a value in bands (1 is the top of the first band, 2 the
  // top of the second) or null for a column nothing was observed in;
  // opt: {w, h, hot, warm} — hot when the second band is out of band (a
  // z scale, whose second band begins at the slider's k), so that band
  // and nothing else takes --heat-2; warm[i] marks a column a baseline
  // could not yet score. Two bands laid over one another in one row
  // (Heer, Kong and Agrawala, CHI 2009): the first in --data at 35 %,
  // the second at 70 % over it. The three states of R5 differ: nothing
  // observed is no ink (a row of none is the dash), observed and quiet
  // a 1 px --rule base, warming a --rule cell as G4's warming cell is.
  // A value past the second band is drawn to the top and said by a 1 px
  // --ink mark along it (R10: by position, not by colour).
  var G3_BANDS = 2;
  function g3(v, opt) {
    var m = [], w = opt.w, h = opt.h, n = v ? v.length : 0, i, any = false;
    var warm = opt.warm || [];
    for (i = 0; i < n; i++) if (gnum(v[i]) || warm[i]) any = true;
    if (!any) { m.push(dash(w, h)); return m; }
    var cw = w / n;
    for (i = 0; i < n; i++) {
      var x = Math.floor(i * cw), cwi = Math.max(1, Math.ceil(cw)), a = v[i];
      if (!gnum(a)) {
        if (warm[i]) m.push(["warm", x, 0, cwi, h, "--rule"]);
        continue;
      }
      if (!(a > 0)) { m.push(["base", x, h - 1, cwi, 1, "--rule"]); continue; }
      var b1 = Math.min(1, a);
      m.push(["hz1", x, h - h * b1, cwi, h * b1, "--data"]);
      if (a > 1) {
        var b2 = Math.min(1, a - 1);
        m.push(["hz2", x, h - h * b2, cwi, h * b2, opt.hot ? "--heat-2" : "--data"]);
      }
      if (a > G3_BANDS) m.push(["clip", x, 0, cwi, 1, "--ink"]);
    }
    return m;
  }
  // G3's columns in bands, from a /api/wifi/channels row. An absolute
  // scale splits its 0 to max in two halves; a z scale's first band is
  // 0 to k sd and its second k to 2k, so the second band begins where
  // the band sparkline's band ends and a channel quieter than normal is
  // flat. rate is the cell's factor to the unit the max is in (60 /
  // col_s for a counter's count per minute, 1 for a gauge); max is the
  // scale's top after R11 (the page keeps it from growing smaller).
  function g3Vals(row, k, rate, max) {
    var v = [], warm = [], i, sc = row && row.scale, z = !!(sc && sc.kind === "z");
    var cells = (row && row.cells) || [];
    for (i = 0; i < cells.length; i++) {
      var c = cells[i];
      warm.push(false);
      if (z) {
        var zi = row.z ? row.z[i] : null;
        if (gnum(zi)) v.push(k > 0 ? Math.max(0, zi) / k : 0);
        else { v.push(null); warm[i] = gnum(c); }
      } else v.push(!gnum(c) ? null : max > 0 ? c * rate / (max / G3_BANDS) : 0);
    }
    return { v: v, warm: warm, hot: z };
  }

  // G7, the event rug (F12). lanes are [{counts, token, spans,
  // spanToken}]: a lane's events per column oldest first, its ink, and
  // the column ranges [a, b] an episode covered (a flood), underlined in
  // spanToken. opt: {w, h, lane, gap, marks} — lane is a lane's height,
  // gap the space under it, marks the x (CSS pixels) of full-height
  // events in --ink (survey sessions). Every lane shares one scale (R3):
  // the tallest column of any lane reaches the lane's height, and
  // g7Max() is the count the caption prints. A column with none draws
  // nothing (P3); one with any is at least 1 px, so one event does not
  // vanish beside thirty. A rug with nothing at all is R5's dash.
  function g7Max(lanes) {
    var max = 0;
    for (var j = 0; lanes && j < lanes.length; j++)
      for (var i = 0, c = lanes[j].counts || []; i < c.length; i++)
        if (gnum(c[i]) && c[i] > max) max = c[i];
    return max;
  }
  function g7(lanes, opt) {
    var m = [], w = opt.w, L = opt.lane, gp = opt.gap || 0, max = g7Max(lanes), i, j;
    for (j = 0; lanes && j < lanes.length; j++) {
      var c = lanes[j].counts || [], n = c.length, cw = n ? w / n : 0, y0 = j * (L + gp);
      for (i = 0; i < n; i++) {
        if (!gnum(c[i]) || !(c[i] > 0)) continue;
        var th = Math.max(1, L * c[i] / max);
        m.push(["tick", Math.floor(i * cw), y0 + L - th, Math.max(1, Math.ceil(cw) - (cw > 3 ? 1 : 0)),
                th, lanes[j].token]);
      }
      var sp = lanes[j].spans || [];
      for (i = 0; n && i < sp.length; i++) {
        var a = sp[i][0] < 0 ? 0 : sp[i][0], b = sp[i][1] > n - 1 ? n - 1 : sp[i][1];
        if (b < a) continue;
        m.push(["span", Math.floor(a * cw), y0 + L, Math.max(1, Math.ceil((b - a + 1) * cw)), 1,
                lanes[j].spanToken || "--sev-crit"]);
      }
    }
    var sm = opt.marks || [];
    for (i = 0; i < sm.length; i++) if (gnum(sm[i])) m.push(["session", sm[i], 0, 2, opt.h, "--ink"]);
    if (!m.length) m.push(dash(w, opt.h));
    return m;
  }

  // G8, the chain timeline (F14). One lane per stage, in the order the
  // chain runs (G8_STAGES), on one time axis of ncol columns, each lane
  // its --rule axis line whether or not it has anything, so a stage not
  // yet seen reads as an empty lane and the next stage is where to look
  // (Endsley's projection). lanes are [{counts, bars}]: counts a lane's
  // events per column oldest first (deauth frames, associations), on one
  // scale for every lane that has them (R3), as G7's ticks; bars an
  // incident's [a, b, sev, open] in columns, b inclusive, a bar from its
  // first to its last observation in the severity colour it reached
  // (R1: severity on alert and chain bars only), with a dot where it
  // began and where it ended when that is inside the window and it has
  // closed. links are [{col, top, word}]: a connector sloth made (the
  // deauth taint, an attribution), --faint from lane top's middle down
  // to the words row under the lanes, its reason in words beside it
  // (P9, P11). labels are each lane's words in the gutter (R10: the
  // severity word with its bar). opt: {w, lane, gutter, ncol, max} —
  // max is the count scale the glyph last drew (R11: grown, never
  // shrunk); g8Max() is the one it draws now. No lane at all: the dash.
  var G8_STAGES = ["deauth", "twin", "assoc", "karma"];
  var G8_WORDS = 12;
  // A 10 px monospace character's advance, near enough to lay words out.
  var G8_CH = 6;
  var SEV_TOKEN = ["--sev-low", "--sev-warn", "--sev-crit"];
  function g8Max(lanes, prev) {
    var max = gnum(prev) && prev > 0 ? prev : 0;
    for (var j = 0; lanes && j < lanes.length; j++)
      for (var i = 0, c = lanes[j].counts || []; i < c.length; i++)
        if (gnum(c[i]) && c[i] > max) max = c[i];
    return max;
  }
  function g8(lanes, links, labels, opt) {
    var m = [], L = opt.lane, gx = opt.gutter || 0, n = opt.ncol > 0 ? opt.ncol : 1, i, j;
    var nl = lanes ? lanes.length : 0, gw = Math.max(1, opt.w - gx), cw = gw / n;
    if (!nl) { m.push(dash(opt.w, L)); return m; }
    var max = g8Max(lanes, opt.max), X = function (c) { return gx + c * cw; };
    for (j = 0; j < nl; j++) {
      var y0 = j * L, mid = y0 + L / 2, ln = lanes[j];
      m.push(["axis", gx, mid, gw, 1, "--rule"]);
      if (labels && labels[j]) m.push(["label", 2, mid, gx - 4, 10, labels[j].token, labels[j].text]);
      var c = ln.counts || [];
      for (i = 0; max > 0 && i < c.length && i < n; i++) {
        if (!gnum(c[i]) || !(c[i] > 0)) continue;
        var th = Math.max(1, (L - 4) * c[i] / max);
        m.push(["tick", Math.floor(X(i)), y0 + L - 2 - th, Math.max(1, Math.ceil(cw) - (cw > 3 ? 1 : 0)),
                th, "--tui-normal"]);
      }
      var b = ln.bars || [];
      for (i = 0; i < b.length; i++) {
        var a0 = b[i][0], b0 = b[i][1];
        if (!gnum(a0) || !gnum(b0) || b0 < 0 || a0 > n - 1 || b0 < a0) continue;
        var tok = SEV_TOKEN[b[i][2] >= 0 && b[i][2] <= 2 ? b[i][2] : 1];
        var xa = X(Math.max(0, a0)), xb = X(Math.min(n - 1, b0) + 1);
        m.push(["bar", xa, mid - 2, Math.max(1, xb - xa), 4, tok]);
        if (a0 >= 0) m.push(["dot", xa, mid, 2.5, 2.5, tok]);
        if (!b[i][3] && b0 <= n - 1) m.push(["dot", xb, mid, 2.5, 2.5, tok]);
      }
    }
    // The words in column order, each after the one before it (the
    // taint and the attribution it settles are often one record, so
    // two connectors share a column and their words would overprint),
    // and drawn back from the right edge rather than past it.
    var wy = nl * L, wx = -1, ks = [];
    for (i = 0; links && i < links.length; i++) {
      var k = links[i];
      if (!gnum(k.col) || k.col < 0 || k.col > n - 1 || !(k.top >= 0 && k.top < nl)) continue;
      ks.push(k);
    }
    ks.sort(function (a, b) { return a.col - b.col; });
    for (i = 0; i < ks.length; i++) {
      var lx = Math.floor(X(ks[i].col) + cw / 2), ly = ks[i].top * L + L / 2;
      var tw = String(ks[i].word).length * G8_CH, tx = Math.max(lx + 3, wx + G8_CH);
      if (tx + tw > opt.w) tx = Math.max(wx + G8_CH, opt.w - tw);
      m.push(["link", lx, ly, 1, wy + 2 - ly, "--faint"]);
      m.push(["word", tx, wy + G8_WORDS / 2, Math.max(1, opt.w - tx), 10, "--muted", ks[i].word]);
      wx = tx + tw;
    }
    return m;
  }
  // g8's height: the lanes, and the words row when a link has words.
  function g8Height(nl, links, lane) {
    return nl * lane + (links && links.length ? G8_WORDS + 2 : 0);
  }
  // A /api/wifi/chain row as g8's lanes, links and labels, and how many
  // stages it has: j is the answer (its from, col_s and cols). A time
  // is the column it falls in; an incident still open at the answer's
  // end (its last observation in the window's last column) has no end
  // dot. The taint joins the deauth lane to the twin lane, so its
  // connector starts at deauth; an attribution is the twin lane's own.
  function g8Lanes(row, j) {
    var cs = j.col_s > 0 ? j.col_s : 1, n = j.cols > 0 ? j.cols : 0, from = j.from;
    var col = function (t) { return Math.floor((t - from) / cs); };
    var bars = function (list) {
      return (list || []).map(function (e) {
        var b = col(e[1]);
        return [col(e[0]), b, e[2], b >= n - 1 ? 1 : 0];
      });
    };
    // A lane's words: its name, the highest severity its bars reached
    // (R10: the word beside the colour), and "none" when it has nothing,
    // in --muted, so an empty lane reads as not yet seen.
    var words = function (name, list, have, extra) {
      var hi = -1;
      for (var i = 0; list && i < list.length; i++) if (list[i][2] > hi) hi = list[i][2];
      var sv = hi === 0 ? " low" : hi === 1 ? " warn" : hi === 2 ? " CRIT" : "";
      return { text: name + (have ? sv + (extra || "") : " none"), token: have ? "--ink" : "--muted" };
    };
    var dc = (row.cells || []).map(function (v) { return gnum(v) ? v : 0; });
    var ac = row.assoc || [];
    var links = [], conf = null;
    (row.links || []).forEach(function (k) {
      if (gnum(k.tainted)) links.push({ col: col(k.tainted), top: 0, word: "tainted \u2191 5 s" });
      if (gnum(k.attributed)) links.push({ col: col(k.attributed), top: 1, word: "attributed \u2191" });
      if (gnum(k.confidence)) conf = k.confidence;
    });
    var nd = 0, na = 0;
    for (var i = 0; i < dc.length; i++) if (dc[i] > 0) nd++;
    for (i = 0; i < ac.length; i++) if (gnum(ac[i]) && ac[i] > 0) na++;
    // An association is a stage only on a BSSID accused or caught
    // luring (a twin or a karma row): elsewhere it is a client joining.
    var lure = (row.twin || []).length + (row.karma || []).length > 0;
    var stages = (nd || (row.floods || []).length ? 1 : 0) + ((row.twin || []).length ? 1 : 0) +
                 (na && lure ? 1 : 0) + ((row.karma || []).length ? 1 : 0);
    var fl = row.floods || [], tw = row.twin || [], ka = row.karma || [];
    return {
      lanes: [{ counts: dc, bars: bars(fl) }, { counts: null, bars: bars(tw) },
              { counts: ac, bars: null }, { counts: null, bars: bars(ka) }],
      labels: [words("deauth", fl, nd > 0 || fl.length > 0),
               words("twin", tw, tw.length > 0, conf !== null ? " " + conf + "%" : ""),
               words("assoc", null, na > 0), words("karma", ka, ka.length > 0)],
      links: links, stages: stages
    };
  }

  // The Flows matrix (F11): sources by destinations as /api/flows/graph
  // ?form=matrix answers them, both axes in address order, subnets
  // grouped by a --rule line where the group changes. Each cell a G6
  // count bar on one scale for the matrix (R3: its largest, printed in
  // the caption), behind its count as a word, and the protocols as a
  // letter each in the cell's corner rather than a hue (no legend). An
  // SMB1 cell keeps the critical colour, bar and number (R10: the
  // caption says what red is). opt: {x0, y0, cw, ch, max} — the label
  // gutter and the header, a cell's size, and the scale the matrix last
  // drew (R11). No cell: the dash.
  var MX_LETTER = { ssh: "S", rdp: "R", smb: "M", snmp: "N", bgp: "B", ldap: "L", kerb: "K" };
  function mxNum(v) {
    if (!gnum(v) || v < 0) return "-";
    if (v < 1000) return String(Math.round(v));
    if (v < 1e6) return (v < 1e4 ? (v / 1e3).toFixed(1) : String(Math.round(v / 1e3))) + "k";
    return (v < 1e7 ? (v / 1e6).toFixed(1) : String(Math.round(v / 1e6))) + "M";
  }
  function mxMax(mx, prev) {
    var max = gnum(prev) && prev > 0 ? prev : 0;
    for (var i = 0, c = (mx && mx.cells) || []; i < c.length; i++)
      if (gnum(c[i].total) && c[i].total > max) max = c[i].total;
    return max;
  }
  function mx(m, opt) {
    var out = [], x0 = opt.x0, y0 = opt.y0, cw = opt.cw, ch = opt.ch, i;
    var srcs = (m && m.srcs) || [], dsts = (m && m.dsts) || [], cells = (m && m.cells) || [];
    var W = x0 + dsts.length * cw, Hh = y0 + srcs.length * ch;
    if (!cells.length) { out.push(dash(Math.max(W, 60), ch)); return out; }
    var own = Object.prototype.hasOwnProperty, max = mxMax(m, opt.max);
    for (i = 1; i < srcs.length; i++)
      if (srcs[i].group !== srcs[i - 1].group) out.push(["grp", 0, y0 + i * ch, W, 1, "--rule"]);
    for (i = 1; i < dsts.length; i++)
      if (dsts[i].group !== dsts[i - 1].group) out.push(["grp", x0 + i * cw, 0, 1, Hh, "--rule"]);
    for (i = 0; i < cells.length; i++) {
      var c = cells[i], x = x0 + c.d * cw, y = y0 + c.s * ch, hot = c.smb1 === true;
      var v = gnum(c.total) && c.total > 0 ? c.total : 0;
      out.push(["bar", x + 2, y + ch * 0.25, Math.max(1, (cw - 4) * Math.min(1, max > 0 ? v / max : 0)),
                ch * 0.5, hot ? "--sev-crit" : "--rule"]);
      out.push(["num", x + 3, y + ch / 2, cw - 6, 10, hot ? "--sev-crit" : "--ink", mxNum(v)]);
      var lt = "";
      for (var k = 0, p = c.protos || []; k < p.length; k++)
        if (typeof p[k] === "string" && own.call(MX_LETTER, p[k])) lt += MX_LETTER[p[k]];
      if (lt) out.push(["proto", x + cw - 2 - 5 * lt.length, y + 4, 5 * lt.length, 7, "--muted", lt]);
    }
    return out;
  }

  // The painter. One for every glyph, because a mark list is all a
  // glyph says: resolve(token) gives the CSS colour of a token, and
  // marks are in CSS pixels on a canvas sized at the device ratio. A
  // gap draws nothing — R5's break in the line is absence of ink.
  function paint(c, marks, resolve) {
    var dpr = window.devicePixelRatio || 1;
    var w = Math.max(1, Math.round(c.clientWidth * dpr));
    var h = Math.max(1, Math.round(c.clientHeight * dpr));
    if (c.width !== w) c.width = w;
    if (c.height !== h) c.height = h;
    var g = c.getContext("2d");
    g.clearRect(0, 0, w, h);
    for (var i = 0; i < marks.length; i++) {
      var m = marks[i], k = m[0];
      if (k === "gap") continue;
      var col = resolve(m[5]);
      g.fillStyle = col;
      g.strokeStyle = col;
      if (typeof m[6] === "string") {
        // A word: its size is the mark's h, its width at most w.
        g.font = Math.round(m[4] * dpr) + "px " + resolve("--font-mono");
        g.textBaseline = "middle";
        g.textAlign = "left";
        g.fillText(m[6], m[1] * dpr, m[2] * dpr, Math.max(1, m[3] * dpr));
      } else if (k === "line") {
        g.lineWidth = Math.max(1, dpr);
        g.beginPath();
        g.moveTo(m[1] * dpr, m[2] * dpr);
        g.lineTo((m[1] + m[3]) * dpr, (m[2] + m[4]) * dpr);
        g.stroke();
      } else if (k === "band" || k === "shade") {
        g.globalAlpha = 0.12;
        g.fillRect(m[1] * dpr, m[2] * dpr, Math.max(1, m[3] * dpr), Math.max(1, m[4] * dpr));
        g.globalAlpha = 1;
      } else if (k === "hz1" || k === "hz2") {
        g.globalAlpha = k === "hz1" ? 0.35 : 0.7;
        g.fillRect(m[1] * dpr, m[2] * dpr, Math.max(1, m[3] * dpr), Math.max(1, m[4] * dpr));
        g.globalAlpha = 1;
      } else if (k === "outline") {
        g.lineWidth = 2 * dpr;
        g.strokeRect((m[1] + 1) * dpr, (m[2] + 1) * dpr, (m[3] - 2) * dpr, (m[4] - 2) * dpr);
      } else if (k === "first") {
        var cx = (m[1] + m[3] / 2) * dpr, cy = (m[2] + m[4] / 2) * dpr, rr = m[4] * dpr / 2;
        g.beginPath();
        g.moveTo(cx, cy - rr); g.lineTo(cx + rr, cy);
        g.lineTo(cx, cy + rr); g.lineTo(cx - rr, cy);
        g.closePath();
        g.fill();
      } else if (k === "dot" || k === "last" || k === "max" || k === "min") {
        g.beginPath();
        g.arc(m[1] * dpr, m[2] * dpr, Math.max(1, m[3] * dpr), 0, 6.283185307179586);
        g.fill();
      } else {
        g.fillRect(m[1] * dpr, m[2] * dpr, Math.max(1, m[3] * dpr), Math.max(1, m[4] * dpr));
      }
    }
  }

  return { g1: g1, g2: g2, g2Clamped: g2Clamped, g2Words: g2Words, isNew: isNew,
           firstCell: firstCell, RSSI_LO: RSSI_LO, RSSI_HI: RSSI_HI, RSSI_REF: RSSI_REF,
           g4: g4, g4Stats: g4Stats, g5: g5, g5Ruler: g5Ruler, g6: g6,
           paint: paint, caption: caption, win: win, scale: scale, dur: dur,
           trend: trend, shared: shared, order: order,
           g3: g3, g3Vals: g3Vals, G3_BANDS: G3_BANDS, g7: g7, g7Max: g7Max,
           cellsFromHex: cellsFromHex, level: level, lineToken: lineToken,
           heatToken: heatToken, g8: g8, g8Max: g8Max, g8Height: g8Height,
           g8Lanes: g8Lanes, G8_STAGES: G8_STAGES, mx: mx, mxMax: mxMax, mxNum: mxNum,
           MX_LETTER: MX_LETTER };
})();
