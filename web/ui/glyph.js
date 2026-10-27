// The glyph layer (docs/web-visual-spec.md §5, slice V0: G1, G5, G6).
//
// Every glyph is two halves. The first maps data and a size to a list
// of marks, each `[kind, x, y, w, h, token]` in CSS pixels with a
// colour *token* and no canvas, no DOM and no theme: it is a pure
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
  // sens, scale}.
  function g1(pts, band, opt) {
    var m = [], w = opt.w, h = opt.h, i, b;
    if (!pts || !pts.length) { m.push(dash(w, h)); return m; }
    var step = opt.step > 0 ? opt.step : 1;
    var from = opt.from, to = opt.to;
    var sc = scale(pts, band, opt.scale || null), lo = sc[0], hi = sc[1];
    var X = function (t) { return to > from ? (t - from) / (to - from) * w : 0; };
    var Y = function (v) { return h - (v - lo) / (hi - lo) * h; };
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
      if (k === "line") {
        g.lineWidth = Math.max(1, dpr);
        g.beginPath();
        g.moveTo(m[1] * dpr, m[2] * dpr);
        g.lineTo((m[1] + m[3]) * dpr, (m[2] + m[4]) * dpr);
        g.stroke();
      } else if (k === "band") {
        g.globalAlpha = 0.12;
        g.fillRect(m[1] * dpr, m[2] * dpr, Math.max(1, m[3] * dpr), Math.max(1, m[4] * dpr));
        g.globalAlpha = 1;
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

  return { g1: g1, g5: g5, g5Ruler: g5Ruler, g6: g6, paint: paint,
           caption: caption, win: win, scale: scale, dur: dur,
           cellsFromHex: cellsFromHex, level: level, lineToken: lineToken,
           heatToken: heatToken };
})();
