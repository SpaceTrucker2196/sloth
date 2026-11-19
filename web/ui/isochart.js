// slothweb: the larger time graphs as isometric waterfalls (owner
// 2026-11-19: "for the larger graphs in the ui when there is a time
// domain express that in the isometric waterfall graph format like we
// have for spectrum using color coding where appropriate"; "all 4").
// Each is SlothIso.grid (web/ui/iso.js), the projection the Spectrum,
// WiFi, BLE Devices and Devices arrivals waterfalls draw with; an
// "isometric" box on its panel, on by default and kept per viewer only
// when off, puts back the flat drawing, which app.js still draws.
// Two shapes:
//   a series against its baseline band (the Overview's now vs normal,
//   the WiFi clients chart, the Activity band chart): time folded into
//   rows, the sensor's local days with the hours across for a window of
//   2 days or more, else equal slices of the window; each column in the
//   colour of where it sits against its band, named in an iso-key;
//   lanes x time (deauth per bssid, probe floods per severity, every
//   key of a metric; the drawer's week, hours across x weekdays): the
//   lanes across, the time cells receding, the newest in front.
// window.SlothIsoChart, the hooks app.js and allkeys.js call:
//   SlothIsoChart.init(h)          once, main()'s helpers lent: fmt,
//                                  hhmmss, prefGet, prefSet
//   SlothIsoChart.box(id, pref, f) an isometric box: on unless kept
//                                  off, f() draws the panel again
//   SlothIsoChart.band(id, d)      a series against its band, or null
//   SlothIsoChart.deauth(j)        the deauth rug's answer
//   SlothIsoChart.pflood(r, ...)   the probe-flood rug's rows
//   SlothIsoChart.allkeys(d)       allkeys.js's ranked rows
//   SlothIsoChart.week(id, wk)     the drawer's week member
// Each picture is drawn on <id>-iso, beside the flat canvas <id>; the
// flat one is hidden by a class while the box is on, and while app.js
// hides the flat one for want of data, iso.css hides this one with it.
// Every string is drawn with fillText or set with textContent.
(function () {
  "use strict";
  var H = null;
  // Where a column sits against its band, and the theme token each is
  // drawn in; the order is where()'s answer.
  var STATES = [
    { k: "above", label: "above its band", tok: "--heat-3", fb: "#ff3f3f" },
    { k: "within", label: "within its band", tok: "--tui-normal", fb: "#2b8f74" },
    { k: "below", label: "below its band", tok: "--data", fb: "#4cebff" },
    { k: "none", label: "no band yet (warming)", tok: "--heat-0", fb: "#626262" }
  ];
  // The keys of a metric drawn as columns, the largest by the legend's
  // order; the time rows a lanes picture folds its cells into.
  var COLS_KEYS = 24, ROWS_MAX = 48;
  var WDAY = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  var P = {};

  function $(id) { return document.getElementById(id); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function cssVar(name, fb) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return v && v.trim() ? v.trim() : fb;
  }
  function pad2(n) { return (n < 10 ? "0" : "") + n; }

  // -- the pure half: web/tests/test_isochart.c pins these out of the page --
  // Where v sits against b ([lo, hi, mean]): 0 above, 1 within, 2 below,
  // 3 no band; -1 for no value.
  function where(v, b) {
    if (!num(v)) return -1;
    if (!b || !num(b[0]) || !num(b[1])) return 3;
    return v > b[1] ? 0 : v < b[0] ? 2 : 1;
  }
  // How a window folds: 2 days or more, the local days (off: the
  // sensor's UTC offset) as rows from the day holding from, the 24
  // hours across; under that, equal slices as rows (15 for 3 h or less,
  // else 24: past 12 rows the grid lays its depth out as a time axis),
  // each cut into as many cells as it holds steps, at most 60; a window
  // of under 60 steps in rows of about 4, at most 8.
  function shape(from, to, step, off) {
    var win = to - from;
    if (win >= 172800) {
      var d0 = from - ((from + off) % 86400 + 86400) % 86400;
      return { days: true, from: d0, n: Math.ceil((to - d0) / 86400), cols: 24, row_s: 86400, cell_s: 3600 };
    }
    var cells = Math.max(1, Math.round(win / Math.max(1, step)));
    // Under 60 steps (a window glyph.win() shrank to a few minutes of
    // data): rows of about 4 cells, at most 8, the ridge spacing's own.
    var n = cells < 60 ? Math.min(8, Math.ceil(cells / 4)) : win <= 10800 ? 15 : 24, row = win / n;
    var cols = Math.max(1, Math.min(60, Math.round(row / Math.max(1, step))));
    return { days: false, from: from, n: n, cols: cols, row_s: row, cell_s: row / cols };
  }
  // The points folded into sh's cells, row k's cell c at k * cols + c:
  // {v, n, b} with v the mean of its points and b the mean of their
  // bands ([lo, hi, mean]) or null where none had one; null for a cell
  // no point fell in.
  function fold(pts, band, sh) {
    var N = sh.n * sh.cols, acc = [], i;
    for (i = 0; i < N; i++) acc.push(null);
    for (i = 0; pts && i < pts.length; i++) {
      var t = pts[i][0], v = pts[i][1];
      if (!num(t) || !num(v) || t < sh.from) continue;
      var k = Math.floor((t - sh.from) / sh.row_s);
      if (k >= sh.n) continue;
      var c = Math.min(sh.cols - 1, Math.floor((t - sh.from - k * sh.row_s) / sh.cell_s));
      var a = acc[k * sh.cols + c] || (acc[k * sh.cols + c] = { v: 0, n: 0, lo: 0, hi: 0, mean: 0, nb: 0 });
      a.v += v; a.n++;
      var b = band && band[i];
      if (b) { a.lo += b[0]; a.hi += b[1]; a.mean += b[2]; a.nb++; }
    }
    return acc.map(function (a) {
      if (!a) return null;
      return { v: a.v / a.n, n: a.n, b: a.nb ? [a.lo / a.nb, a.hi / a.nb, a.mean / a.nb] : null };
    });
  }
  // A lane's cells folded g to a row: summed ("sum"), the largest
  // ("max") or the mean of those with a value ("mean"); null for a row
  // with none.
  function foldRow(cells, g, how) {
    var out = [];
    for (var a = 0; a < cells.length; a += g) {
      var s = 0, n = 0, mx = null;
      for (var i = a; i < a + g && i < cells.length; i++) {
        if (!num(cells[i])) continue;
        s += cells[i]; n++;
        if (mx === null || cells[i] > mx) mx = cells[i];
      }
      out.push(!n ? null : how === "max" ? mx : how === "mean" ? s / n : s);
    }
    return out;
  }
  // Is row k of a lane (g cells a row) under one of spans ([a, b] in
  // cells, both ends in)?
  function inSpan(spans, g, k) {
    for (var i = 0; spans && i < spans.length; i++)
      if (Math.floor(spans[i][0] / g) <= k && k <= Math.floor(spans[i][1] / g)) return true;
    return false;
  }
  // The probe-flood rug's lanes (air.js floodRug()'s counting): a lane
  // per severity with any finding in [from, to), worst first; counts
  // the findings begun in each of cols cells, spans each one's first to
  // last sighting in cells.
  function sevLanes(rows, from, to, cols) {
    var col_s = (to - from) / cols, out = [];
    function col(t) { return Math.max(0, Math.min(cols - 1, Math.floor((t - from) / col_s))); }
    for (var sv = 2; sv >= 0; sv--) {
      var counts = [], spans = [], i;
      for (i = 0; i < cols; i++) counts.push(0);
      for (i = 0; rows && i < rows.length; i++) {
        var r = rows[i];
        if (r.sev !== sv || !num(r.first_seen) || !num(r.last_seen)) continue;
        if (r.last_seen < from || r.first_seen >= to) continue;
        if (r.first_seen >= from) counts[col(r.first_seen)]++;
        spans.push([col(r.first_seen), col(r.last_seen)]);
      }
      if (spans.length) out.push({ sev: sv, counts: counts, spans: spans });
    }
    return out;
  }
  // A key's points ([t, v], oldest first) as n rows of row_s from from,
  // folded as foldRow() folds.
  function binPts(pts, from, row_s, n, how) {
    var cells = [], i;
    for (i = 0; i < n; i++) cells.push([]);
    for (i = 0; pts && i < pts.length; i++) {
      var k = Math.floor((pts[i][0] - from) / row_s);
      if (k >= 0 && k < n && num(pts[i][1])) cells[k].push(pts[i][1]);
    }
    return cells.map(function (c) { return c.length ? foldRow(c, c.length, how)[0] : null; });
  }
  // The keys drawn as columns: the first max of the legend's order, the
  // picked one (pick its index, -1 none) in the last place when it is
  // not among them.
  function keyCols(n, max, pick) {
    var out = [];
    for (var i = 0; i < n && i < max; i++) out.push(i);
    if (pick >= max && pick < n) out[out.length - 1] = pick;
    return out;
  }
  // The week's cell for weekday row k (0 Monday, at the back) and hour
  // c, and its state: 0 fed (warm weeks or more), 1 provisional, -1
  // never observed.
  function weekState(cell, warm) {
    if (!cell || !num(cell[1]) || cell[1] <= 0) return -1;
    return cell[1] >= warm ? 0 : 1;
  }

  // -- the drawing half --
  function chart(id) {
    if (!P[id]) P[id] = { st: { off: null, dirty: true, geo: null, hover: null, o: null }, on: true, d: null, tip: null };
    return P[id];
  }
  function colors() { return STATES.map(function (s) { return cssVar(s.tok, s.fb); }); }
  // A key under the picture: a swatch then its name, each pair once.
  function key(id, items) {
    var box = $(id + "-iso-key");
    if (!box) return;
    while (box.firstChild) box.removeChild(box.firstChild);
    items.forEach(function (d) {
      var it = document.createElement("span"), sw = document.createElement("span");
      it.className = "it"; sw.className = "sw";
      sw.style.background = d.color;
      it.appendChild(sw);
      it.appendChild(document.createTextNode(d.label));
      box.appendChild(it);
    });
  }
  // The flat canvas hidden by its class while the box is on; this one,
  // and its key, while it is off.
  function sync(id) {
    var p = chart(id), f = $(id), cv = $(id + "-iso"), k = $(id + "-iso-key");
    if (f) f.classList.toggle("iso-off", p.on);
    if (cv) cv.hidden = !p.on;
    if (k) k.hidden = !p.on;
    if (!p.on) { p.st.hover = null; tipShow(null, null); }
    return p.on && cv && f && !f.hidden ? cv : null;
  }
  function paint(id) {
    var p = chart(id), cv = sync(id);
    if (!cv || !p.d || !window.SlothIso) return;
    var o = p.d.grid();
    p.tip = p.d.tip;
    p.click = p.d.click || null;
    SlothIso.grid(cv, p.st, o);
  }
  function tipShow(lines, ev) {
    var box = $("isoc-tip");
    if (box && window.SlothIso) SlothIso.tip(box, lines, ev || { clientX: 0, clientY: 0 });
  }
  // A column's offset into its row, exact to the second: rounded to
  // the minute, a row of 10 s cells read "+1m" three times over.
  function dur(s) {
    s = Math.round(s);
    if (s < 60) return s + "s";
    var sec = s % 60;
    if (s < 3600) return Math.floor(s / 60) + "m" + (sec ? pad2(sec) + "s" : "");
    var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    return h + "h" + (m || sec ? pad2(m) : "") + (sec ? "m" + pad2(sec) + "s" : "");
  }
  function dayWord(ts, off) {
    var d = new Date((ts + off) * 1000);
    return d.getUTCFullYear() + "-" + pad2(d.getUTCMonth() + 1) + "-" + pad2(d.getUTCDate());
  }
  function hm(t) { return H.hhmmss(t).slice(0, 5); }
  // hh:mm at t on the clock of UTC offset off: a day-folded picture's
  // columns are the sensor's hours, so its tooltip reads that clock too.
  function hmAt(t, off) {
    var d = new Date((t + off) * 1000);
    return pad2(d.getUTCHours()) + ":" + pad2(d.getUTCMinutes());
  }
  // This browser's offset from UTC at t, read off its own clock's
  // fields, as H.hhmmss() reads them.
  function localOff(t) {
    var d = new Date(t * 1000);
    return Math.round((Date.UTC(d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(),
                                d.getMinutes(), d.getSeconds()) - Math.floor(t) * 1000) / 1000);
  }

  // A series against its band. d: {pts, band (bands()'s, one a point),
  // from, to, step, off (the baseline's utc_offset_s), unit, now}; null
  // when the flat chart has nothing to draw either.
  function band(id, d) {
    var p = chart(id);
    if (!d) { p.d = null; sync(id); return; }
    // The baseline's offset (the sensor's, as its bands are), else this
    // browser's, the page's every other clock.
    var off = num(d.off) ? d.off : localOff(d.from);
    var sh = shape(d.from, d.to, d.step, off), cells = fold(d.pts, d.band, sh);
    var lo = 0, hi = 0, unit = d.unit ? " " + d.unit : "", any = false;
    cells.forEach(function (c) { if (c) { any = true; if (c.v > hi) hi = c.v; if (c.v < lo) lo = c.v; } });
    if (!(hi > lo)) hi = lo + 1;
    function at(k, c) { return k >= 0 && k < sh.n && c >= 0 && c < sh.cols ? cells[k * sh.cols + c] : null; }
    function t0(k, c) { return sh.from + k * sh.row_s + c * sh.cell_s; }
    function when(t) { return sh.days ? dayWord(t, off) + " " + hmAt(t, off) : hm(t); }
    function till(t) { return sh.days ? hmAt(t, off) : hm(t); }
    p.d = {
      grid: function () {
        var cs = colors(), cols = [], now = null;
        key(id, STATES.map(function (s, i) { return { label: s.label, color: cs[i] }; }));
        for (var c = 0; c < sh.cols; c++)
          cols.push(sh.days ? { label: pad2(c) + ":00", short: pad2(c) } : { label: "+" + dur(c * sh.cell_s) });
        if (num(d.now) && d.now >= sh.from) {
          var nk = Math.floor((d.now - sh.from) / sh.row_s);
          var nc = Math.min(sh.cols - 1, Math.floor((d.now - sh.from - nk * sh.row_s) / sh.cell_s));
          if (at(nk, nc)) now = { k: nk, c: nc };
        }
        return {
          cols: cols, n: any ? sh.n : 0, from: sh.from, col_s: sh.row_s,
          // A cell with a value is never drawn under a sliver, so a zero
          // still shows where it sits against its band.
          value: function (k, c) { var x = at(k, c); return x ? Math.max(x.v, lo + (hi - lo) * 0.03) : null; },
          segments: function (k, c) {
            var x = at(k, c);
            return x ? [{ f: 1, color: cs[where(x.v, x.b)] }] : null;
          },
          lo: lo, hi: hi, ticks: [lo, (lo + hi) / 2, hi], unit: d.unit || "", fmt: H.fmt,
          clock: function (t) { return sh.days ? dayWord(t, off).slice(5) : hm(t); },
          sel: null, pick: now ? { cols: [], color: function () { return cssVar("--signal", "#ff8c26"); },
                                   cells: [now], cellColor: cssVar("--signal", "#ff8c26") } : null,
          empty: "no data"
        };
      },
      tip: function (a) {
        var x = at(a.k, a.c);
        if (!x) return null;
        var s = t0(a.k, a.c), w = where(x.v, x.b);
        return [[when(s) + " to " + till(s + sh.cell_s)],
                [H.fmt(x.v) + unit + (x.n > 1 ? " (mean of " + x.n + ")" : "")],
                [x.b ? "band " + H.fmt(x.b[0]) + " to " + H.fmt(x.b[1]) + unit + ", mean " + H.fmt(x.b[2])
                     : "no band for this hour yet (warming)", true],
                [STATES[w].label, true]];
      }
    };
    paint(id);
  }

  // /api/wifi/chain's single-stage bssids (app.js's j for SlothAir.rug):
  // a column per bssid air.js draws a lane for, in its channel's colour;
  // the cells folded to at most ROWS_MAX rows; a row in a DEAUTH_FLOOD
  // episode drawn in the critical colour and ticked at its foot.
  function deauth(j) {
    var id = "w-deauth", p = chart(id);
    var rows = ((j && j.bssids) || []).filter(SlothAir.busy).slice(0, 12);
    if (!rows.length) { p.d = null; sync(id); return; }
    var nc = num(j.cols) ? j.cols : 0, g = Math.max(1, Math.ceil(nc / ROWS_MAX)), n = Math.ceil(nc / g);
    var lanes = rows.map(function (r) {
      var spans = (r.floods || []).map(function (f) {
        return [Math.floor((f[0] - j.from) / j.col_s), Math.floor((f[1] - j.from) / j.col_s)];
      });
      var v = foldRow(r.cells || [], g, "sum"), tot = 0;
      v.forEach(function (x) { if (num(x)) tot += x; });
      return { bssid: String(r.bssid), v: v, spans: spans, total: tot };
    });
    var hi = 0;
    lanes.forEach(function (l) { l.v.forEach(function (x) { if (num(x) && x > hi) hi = x; }); });
    var row_s = j.col_s * g;
    p.d = {
      grid: function () {
        // An unknown channel in --tui-dim, as the flat rug writes its name.
        var crit = cssVar("--sev-crit", "#ff3f3f"), dim = cssVar("--tui-dim", "#00875f");
        var cc = lanes.map(function (l) {
          var ch = window.SlothChan ? SlothChan.of("mac", l.bssid) : null;
          return ch !== null && ch !== undefined ? SlothChan.rgb(ch) : dim;
        });
        key(id, [{ label: "each bssid in its channel's colour; this one: channel unknown", color: dim },
                 { label: "in a DEAUTH_FLOOD episode", color: crit }]);
        return {
          cols: lanes.map(function (l, c) { return { label: l.bssid, short: l.bssid.slice(-5), floor: { color: cc[c] }, cap: cc[c] }; }),
          n: n, from: j.from, col_s: row_s,
          value: function (k, c) { var x = lanes[c].v[k]; return num(x) && x > 0 ? x : null; },
          segments: function (k, c) { return [{ f: 1, color: inSpan(lanes[c].spans, g, k) ? crit : cc[c] }]; },
          lo: 0, hi: hi > 0 ? hi : 1, ticks: hi > 0 ? [0, hi / 2, hi] : [0], unit: "frames", fmt: H.fmt,
          clock: hm, sel: null,
          lane: { name: "frames", count: function (c) { return lanes[c].total; }, color: function (c) { return cc[c]; },
                  foot: function (k, c) { return inSpan(lanes[c].spans, g, k) ? crit : null; } },
          empty: "0 deauth in the window"
        };
      },
      tip: function (a) {
        var l = lanes[a.c];
        if (!l) return null;
        var s = j.from + a.k * row_s, x = l.v[a.k];
        return [[l.bssid], [hm(s) + " to " + hm(s + row_s)],
                [(num(x) ? H.fmt(x) : "0") + " deauth frame" + (x === 1 ? "" : "s")],
                [inSpan(l.spans, g, a.k) ? "in a DEAUTH_FLOOD episode" : "no flood episode", true]];
      }
    };
    paint(id);
  }

  // The probe-flood rug's rows: a column per severity with a finding, in
  // its colour; a row's height the findings begun in it, ticked at its
  // foot while one is open (first to last sighting).
  var SEV_TOK = ["--sev-low", "--sev-warn", "--sev-crit"], SEV_FB = ["#6bffcc", "#ff8c26", "#ff3f3f"];
  var SEV_WORD = ["low", "warn", "crit"];
  function pflood(rows, from, to, cols) {
    var id = "w-pflood", p = chart(id), lanes = rows ? sevLanes(rows, from, to, cols) : [];
    if (!lanes.length) { p.d = null; sync(id); return; }
    var g = Math.max(1, Math.ceil(cols / ROWS_MAX)), n = Math.ceil(cols / g), row_s = (to - from) / cols * g, hi = 0;
    lanes.forEach(function (l) {
      l.v = foldRow(l.counts, g, "sum");
      l.v.forEach(function (x) { if (num(x) && x > hi) hi = x; });
    });
    p.d = {
      grid: function () {
        var cc = lanes.map(function (l) { return cssVar(SEV_TOK[l.sev], SEV_FB[l.sev]); });
        key(id, lanes.map(function (l, c) { return { label: SEV_WORD[l.sev] + ": findings begun; a tick while one is open", color: cc[c] }; }));
        return {
          cols: lanes.map(function (l, c) { return { label: SEV_WORD[l.sev], floor: { color: cc[c] }, cap: cc[c] }; }),
          n: n, from: from, col_s: row_s,
          value: function (k, c) { var x = lanes[c].v[k]; return num(x) && x > 0 ? x : null; },
          segments: function (k, c) { return [{ f: 1, color: cc[c] }]; },
          lo: 0, hi: hi > 0 ? hi : 1, ticks: hi > 0 ? [0, hi] : [0], unit: "begun", fmt: H.fmt,
          clock: hm, sel: null,
          lane: { name: "found", count: function (c) { return lanes[c].spans.length; }, color: function (c) { return cc[c]; },
                  foot: function (k, c) { return inSpan(lanes[c].spans, g, k) ? cc[c] : null; } },
          empty: "0 probe floods in the window"
        };
      },
      tip: function (a) {
        var l = lanes[a.c];
        if (!l) return null;
        var s = from + a.k * row_s, x = l.v[a.k], open = 0;
        l.spans.forEach(function (sp) { if (Math.floor(sp[0] / g) <= a.k && a.k <= Math.floor(sp[1] / g)) open++; });
        return [[SEV_WORD[l.sev] + " PROBE_FLOOD"], [hm(s) + " to " + hm(s + row_s)],
                [(num(x) ? x : 0) + " begun"], [open + " open in the cell", true]];
      }
    };
    paint(id);
  }

  // allkeys.js's graph. d: {rows (ranked, each {key, k, pts}), from, to,
  // cell (seconds a point), presence, pick (index, -1 none), unit,
  // onPick(key)}: a column per key, the first COLS_KEYS of the legend's
  // order and the picked one, each in its key's colour (--k-N, the
  // legend's swatch), every other faded while one is picked; the cells
  // folded to at most ROWS_MAX rows (a mean, a presence any).
  function allkeys(d) {
    var id = "ak-chart", p = chart(id);
    if (!d || !d.rows.length) { p.d = null; sync(id); return; }
    var span = Math.max(1, d.to - d.from), cells = Math.max(1, Math.round(span / Math.max(1, d.cell)));
    var g = Math.max(1, Math.ceil(cells / ROWS_MAX)), n = Math.ceil(cells / g), row_s = d.cell * g;
    var idx = keyCols(d.rows.length, COLS_KEYS, d.pick), how = d.presence ? "max" : "mean";
    var lanes = idx.map(function (i) { return { i: i, r: d.rows[i], v: binPts(d.rows[i].pts, d.from, row_s, n, how) }; });
    var lo = 0, hi = 0;
    lanes.forEach(function (l) { l.v.forEach(function (x) { if (num(x)) { if (x > hi) hi = x; if (x < lo) lo = x; } }); });
    if (!(hi > lo)) hi = lo + 1;
    function when(t) { return span <= 86400 ? hm(t) : dayWord(t, localOff(t)) + " " + hm(t); }
    p.d = {
      grid: function () {
        var cc = lanes.map(function (l) { return cssVar("--k-" + l.r.k, "#43d6a8"); });
        key(id, []);
        var pc = -1;
        lanes.forEach(function (l, c) { if (l.i === d.pick) pc = c; });
        return {
          cols: lanes.map(function (l, c) {
            return { label: (l.i + 1) + " " + (l.r.key || "(global)"), short: String(l.i + 1), floor: { color: cc[c] }, cap: cc[c] };
          }),
          n: n, from: d.from, col_s: row_s,
          value: function (k, c) { var x = lanes[c].v[k]; return num(x) ? Math.max(x, lo + (hi - lo) * 0.02) : null; },
          segments: function (k, c) { return [{ f: 1, color: cc[c], alpha: pc >= 0 && pc !== c ? 0.3 : 1 }]; },
          lo: lo, hi: hi, ticks: [lo, (lo + hi) / 2, hi], unit: d.unit || "", fmt: H.fmt,
          clock: function (t) { return span <= 86400 ? hm(t) : when(t).slice(5); }, sel: null,
          pick: pc >= 0 ? { cols: [pc], color: function () { return cssVar("--signal", "#ff8c26"); } } : null,
          empty: "no data"
        };
      },
      tip: function (a) {
        var l = lanes[a.c];
        if (!l) return null;
        var s = d.from + a.k * row_s, x = l.v[a.k];
        return [[(l.i + 1) + "  " + (l.r.key || "(global)")], [when(s) + " to " + hm(s + row_s)],
                [!num(x) ? "no data" : d.presence ? (x >= 0.5 ? "present" : "absent")
                                     : H.fmt(x) + (d.unit ? " " + d.unit : "") + (g > 1 ? " (mean of " + g + " cells)" : "")],
                ["click: show this key alone", true]];
      },
      click: function (a) { var l = lanes[a.c]; if (l && d.onPick) d.onPick(l.r.key); }
    };
    paint(id);
  }

  // The drawer's week member ({cells: 168 of [share, weeks], warm_n,
  // now_cell}): the 24 hours across, the weekdays receding, Monday at
  // the back; a fed cell's height and heat its share of weeks present,
  // a provisional one (under warm_n weeks) in --tui-dim, a cell never
  // observed not drawn; now's cell marked.
  function week(id, wk) {
    var p = chart(id), cl = wk && wk.cells && wk.cells.length === 168 ? wk.cells : null;
    if (!cl) {
      p.d = { grid: function () { key(id, []); return { cols: [], n: 0, empty: "no week observed yet" }; },
              tip: function () { return null; } };
      paint(id);
      return;
    }
    var warm = num(wk.warm_n) ? wk.warm_n : 3;
    function at(k, c) { return k >= 0 && k < 7 && c >= 0 && c < 24 ? cl[k * 24 + c] : null; }
    p.d = {
      grid: function () {
        var dim = cssVar("--tui-dim", "#5a536e"), cols = [], now = null;
        key(id, [{ label: "a low share of weeks present", color: cssVar("--heat-0", "#2b8f74") },
                 { label: "a high share (height and heat alike)", color: cssVar("--heat-3", "#ff3f3f") },
                 { label: "provisional (under " + warm + " weeks)", color: dim },
                 { label: "now", color: cssVar("--signal", "#ff8c26") }]);
        for (var c = 0; c < 24; c++) cols.push({ label: pad2(c) + ":00", short: pad2(c) });
        if (num(wk.now_cell) && wk.now_cell >= 0 && wk.now_cell < 168 && weekState(cl[wk.now_cell], warm) >= 0)
          now = { k: Math.floor(wk.now_cell / 24), c: wk.now_cell % 24 };
        return {
          cols: cols, n: 7, from: 0, col_s: 1,
          value: function (k, c) {
            var x = at(k, c);
            return weekState(x, warm) < 0 ? null : Math.max(num(x[0]) ? x[0] : 0, 0.03);
          },
          segments: function (k, c) { return weekState(at(k, c), warm) === 1 ? [{ f: 1, color: dim }] : null; },
          lo: 0, hi: 1, ticks: [0, 0.5, 1], unit: "share", fmt: function (v) { return v.toFixed(1); },
          clock: function (k) { return WDAY[k] || ""; }, sel: now,
          empty: "no week yet"
        };
      },
      tip: function (a) {
        var x = at(a.k, a.c), s = weekState(x, warm);
        if (s < 0) return [[WDAY[a.k] + " " + pad2(a.c) + ":00"], ["not yet observed", true]];
        return [[WDAY[a.k] + " " + pad2(a.c) + ":00 to " + pad2((a.c + 1) % 24) + ":00"],
                ["present " + Math.round((num(x[0]) ? x[0] : 0) * 100) + "% of " + x[1] + " week" + (x[1] === 1 ? "" : "s")],
                [s ? "provisional: under " + warm + " weeks" : "fed", true]];
      }
    };
    paint(id);
  }

  // An isometric box: on unless kept off (the default kept as no value),
  // its charts synced, redraw() drawing the panel again either way.
  function box(bid, pref, ids, redraw) {
    var b = $(bid);
    if (!b) return;
    var on = H.prefGet(pref) !== false;
    b.checked = on;
    ids.forEach(function (id) { chart(id).on = on; sync(id); });
    b.addEventListener("change", function () {
      on = b.checked;
      H.prefSet(pref, on ? null : false);
      ids.forEach(function (id) { chart(id).on = on; chart(id).st.dirty = true; sync(id); });
      redraw();
    });
    ids.forEach(function (id) {
      var cv = $(id + "-iso");
      if (!cv) return;
      cv.addEventListener("pointermove", function (ev) {
        var p = chart(id), at = p.d ? SlothIso.at(cv, p.st, ev) : null, lines = at && p.tip ? p.tip(at) : null;
        p.st.hover = lines ? at : null;
        tipShow(lines, ev);
        SlothIso.grid(cv, p.st);
      });
      cv.addEventListener("pointerleave", function (ev) {
        var p = chart(id);
        if (!p.st.hover) return;
        p.st.hover = null;
        tipShow(null, ev);
        SlothIso.grid(cv, p.st);
      });
      cv.addEventListener("click", function (ev) {
        var p = chart(id), at = p.d && p.click ? SlothIso.at(cv, p.st, ev) : null;
        if (at) p.click(at);
      });
    });
  }

  window.addEventListener("resize", function () {
    Object.keys(P).forEach(function (id) { if (P[id].d) { P[id].st.dirty = true; paint(id); } });
  });

  window.SlothIsoChart = {
    init: function (h) { H = h; },
    box: box, band: band, deauth: deauth, pflood: pflood, allkeys: allkeys, week: week,
    STATES: STATES, where: where, shape: shape, fold: fold, foldRow: foldRow, inSpan: inSpan,
    sevLanes: sevLanes, binPts: binPts, keyCols: keyCols, weekState: weekState
  };
})();
