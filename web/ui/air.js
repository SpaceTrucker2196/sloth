// slothweb: the WiFi view's air picture (docs/web-visual-spec.md §6.3,
// #171 slice V3): G3's horizon block with its drill-in, and the chains
// panel's G7 rug. The geometry is glyph.js's; this module lays the
// strips out on their canvases and writes the labels.
// window.SlothAir, the hooks app.js calls:
//   SlothAir.init(h)               once, main()'s helpers lent
//   SlothAir.horizon(c, rows, o)   the G3 block on c, one strip per
//                                  channel row; its picking geometry,
//                                  the caption's counts and R4's window
//   SlothAir.drill(c, rows, col)   the picked column beside it: each
//                                  channel's top five transmitters
//                                  stacked in their TUI colours
//   SlothAir.rug(c, j)             /api/wifi/deauth as G7 on c: {max,
//                                  lanes, busy}, the tallest count, the
//                                  lanes drawn (0: c collapsed) and the
//                                  bssids with a frame or a flood
// Channel keys and BSSIDs are drawn with fillText, never as markup.
(function () {
  "use strict";
  var H = null;
  // §5 G3: 18 px a row; the key, and its scale's top, in a gutter at
  // its left.
  var ROW = 18, LABEL = 76;
  // §5 G7: a lane per bssid, its labels in a gutter as the timeline had.
  var LANE = 12, GAP = 4, BSS = 128, LANES = 12;

  function num(v) { return typeof v === "number" && isFinite(v); }
  function shift(marks, dx, dy) {
    return marks.map(function (m) { return [m[0], m[1] + dx, m[2] + dy, m[3], m[4], m[5]]; });
  }

  // o: {heat, k, g3max, cur} — the metric's answer, the slider's k,
  // the per-channel scale tops R11 keeps (grown, never shrunk, until
  // the metric or the scope changes), and the picked cell or null.
  function horizon(c, rows, o) {
    var hz = o.heat, cols = hz && num(hz.cols) ? hz.cols : 0;
    c.style.height = Math.max(1, rows.length) * ROW + "px";
    var w = c.clientWidth, gw = Math.max(1, w - LABEL);
    var rate = hz && hz.kind === "counter" && hz.col_s > 0 ? 60 / hz.col_s : 1;
    var marks = [], out = { nz: 0, nabs: 0, warming: 0, clipped: 0, geo: null, win: null };
    // R4 for the block: when the columns any channel was observed in
    // span less than a tenth of the window (a sensor up for 6 min of an
    // hour), every strip draws those columns only, and the caption says
    // so (glyph.win()'s words). One window for every row, so the rows
    // still compare (P4).
    var c0 = 0, c1 = cols - 1, lo = -1, hi = -1;
    rows.forEach(function (r) {
      var cl = (r.heat && r.heat.cells) || [];
      for (var k = 0; k < cl.length && k < cols; k++)
        if (num(cl[k])) { if (lo < 0) lo = k; if (k > hi) hi = k; }
    });
    if (lo >= 0 && hz.col_s > 0) {
      var wn = glyph.win([[hz.from + lo * hz.col_s, 0], [hz.from + (hi + 1) * hz.col_s, 0]],
                         hz.from, hz.to);
      if (wn.shrunk) { c0 = lo; c1 = hi; out.win = wn; }
    }
    var tops = [];
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i], y = i * ROW, row = r.heat, sc = row && row.scale, max = 0;
      if (i && rows[i - 1].band !== r.band) marks.push(["rule", 0, y, w, 1, "--rule"]);
      if (sc && sc.kind === "z") out.nz++;
      else if (sc) {
        out.nabs++;
        max = o.g3max[r.key] = Math.max(o.g3max[r.key] || 0, num(sc.max) ? sc.max : 0);
      }
      tops.push(sc && sc.kind === "z" ? "z" : sc ? H.fmt(max) : "");
      if (row) row = { scale: sc, cells: (row.cells || []).slice(c0, c1 + 1),
                       z: row.z ? row.z.slice(c0, c1 + 1) : null };
      var gv = glyph.g3Vals(row, o.k, rate, max);
      for (var k = 0; k < gv.warm.length; k++) if (gv.warm[k]) out.warming++;
      var mk = glyph.g3(gv.v, { w: gw, h: ROW - 2, hot: gv.hot, warm: gv.warm });
      for (k = 0; k < mk.length; k++) if (mk[k][0] === "clip") out.clipped++;
      marks = marks.concat(shift(mk, LABEL, y + 2));
    }
    glyph.paint(c, marks, H.tok);
    var dpr = window.devicePixelRatio || 1, g = c.getContext("2d");
    g.font = 10 * dpr + "px " + H.css("--font-mono");
    g.textBaseline = "middle";
    // R3 and P10: each strip is on its own scale, so its top is printed
    // beside its key ("z" for a z strip: the two scales differ).
    rows.forEach(function (r, j) {
      var ty = (j * ROW + ROW / 2 + 1) * dpr;
      g.fillStyle = H.tok("--muted");
      g.textAlign = "left";
      g.fillText(r.key, 2 * dpr, ty);
      g.fillStyle = H.tok("--faint");
      g.textAlign = "right";
      g.fillText(tops[j], (LABEL - 4) * dpr, ty);
    });
    g.textAlign = "left";
    if (!cols) return out;
    var cw = gw / (c1 - c0 + 1);
    out.geo = { x0: LABEL * dpr, rh: ROW * dpr, cw: cw * dpr, cols: cols, c0: c0, c1: c1,
                col_s: hz.col_s, from: hz.from, dpr: dpr };
    // The picked column, once, in the one accent (P6).
    var cur = o.cur;
    if (cur && cur.c >= c0 && cur.c <= c1) {
      g.strokeStyle = H.tok("--signal");
      g.lineWidth = Math.max(1, dpr);
      g.strokeRect((LABEL + (cur.c - c0) * cw) * dpr + 0.5, 0.5, Math.max(dpr, cw * dpr - 1),
                   rows.length * ROW * dpr - 1);
    }
    return out;
  }

  // The drill-in (owner ruling of 2026-10-26: both): for the picked
  // column, each channel's row at the height of its strip, the cell's
  // five busiest transmitters as bands of its width by their share of
  // its frames, an AP in its SSID's colour and a client in its MAC's
  // (the stacking work of 2026-10-23), grey the rest, on the monitor
  // radio's ground. col -1: nothing picked, an empty column.
  function drill(c, rows, col) {
    c.style.height = Math.max(1, rows.length) * ROW + "px";
    var T = H.theme(), dpr = H.sizeCanvas(c), g = c.getContext("2d"), W = c.width;
    g.clearRect(0, 0, W, c.height);
    if (col < 0) return;
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i], m = r.mix && r.mix.cells ? r.mix.cells[col] : null;
      var y = (i * ROW + 2) * dpr, hh = (ROW - 2) * dpr;
      g.fillStyle = T.mon;
      g.fillRect(0, y, W, hh);
      if (!Array.isArray(m) || !num(m[0]) || m[0] <= 0) continue;
      var x = 0;
      for (var e = 2; e + 1 < m.length; e += 2) {
        var bw = W * m[e + 1] / m[0];
        g.fillStyle = H.txColor(H.txOf(m[e]));
        g.fillRect(x, y, bw, hh);
        x += bw;
      }
      if (num(m[1]) && m[1] > 0) {
        g.fillStyle = T.heat[0];
        g.fillRect(x, y, W * m[1] / m[0], hh);
      }
    }
  }

  // §6.3's chains panel until G8 (V4): the deauth frames as G7, one
  // lane per bssid on one shared scale (R3, where the timeline drew each
  // row against its own busiest), and sloth.db's DEAUTH_FLOOD episodes
  // against it as a --sev-crit underline across the columns they cover.
  // A lane only for a bssid with a frame or a flood in the window: the
  // route lists every key the rollup holds, so a bssid that deauthed
  // hours before a 1 h window is listed with every cell empty, and
  // drawing its name over nothing would be the empty box F16 removes.
  // No such bssid: the canvas collapses and the caption says so.
  function busy(r) {
    if ((r.floods || []).length) return true;
    for (var i = 0, c = r.cells || []; i < c.length; i++) if (num(c[i]) && c[i] > 0) return true;
    return false;
  }
  function rug(c, j) {
    var all = ((j && j.bssids) || []).filter(busy), rows = all.slice(0, LANES);
    c.hidden = !rows.length;
    if (!rows.length) return { max: 0, lanes: 0, busy: 0 };
    c.style.height = rows.length * (LANE + GAP) + "px";
    var gw = Math.max(1, c.clientWidth - BSS);
    var lanes = rows.map(function (r) {
      var spans = (r.floods || []).map(function (f) {
        return [Math.floor((f[0] - j.from) / j.col_s), Math.floor((f[1] - j.from) / j.col_s)];
      });
      return { counts: r.cells || [], token: "--tui-normal", spans: spans, spanToken: "--sev-crit" };
    });
    glyph.paint(c, shift(glyph.g7(lanes, { w: gw, h: c.clientHeight, lane: LANE, gap: GAP }), BSS, 0),
                H.tok);
    var dpr = window.devicePixelRatio || 1, g = c.getContext("2d");
    g.font = 10 * dpr + "px " + H.css("--font-mono");
    g.textBaseline = "middle";
    g.fillStyle = H.tok("--tui-dim");
    rows.forEach(function (r, i) {
      g.fillText(String(r.bssid), 2 * dpr, (i * (LANE + GAP) + LANE / 2) * dpr);
    });
    return { max: glyph.g7Max(lanes), lanes: rows.length, busy: all.length };
  }

  // §6.3's chains panel, the probe-flood rug (#195; V3 left it for want
  // of the alert type on the page, which /api/alerts now takes by name).
  // rows are /api/alerts' PROBE_FLOOD rows, one per alert key; a lane
  // per severity that has any, in that severity's colour (R1: severity
  // on alert lanes), top lane the worst. A tick where a key was first
  // seen, its height the keys begun in the column on one scale for every
  // lane (R3); an underline from the key's first to its last sighting,
  // which is the finding's span, quiet gaps between its incidents
  // included (the caption says so). None in the window: the canvas
  // collapses and the caption says so (F16). Returns {max, lanes, keys}.
  var SEV_TOK = ["--sev-low", "--sev-warn", "--sev-crit"];
  var SEV_LANE = ["low", "warn", "crit"];
  function floodRug(c, rows, from, to, cols) {
    var col_s = (to - from) / cols, lanes = [], names = [], keys = 0;
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
      if (!spans.length) continue;
      keys += spans.length;
      lanes.push({ counts: counts, token: SEV_TOK[sv], spans: spans, spanToken: SEV_TOK[sv] });
      names.push(SEV_LANE[sv]);
    }
    c.hidden = !lanes.length;
    if (!lanes.length) return { max: 0, lanes: 0, keys: 0 };
    c.style.height = lanes.length * (LANE + GAP) + "px";
    var gw = Math.max(1, c.clientWidth - BSS);
    glyph.paint(c, shift(glyph.g7(lanes, { w: gw, h: c.clientHeight, lane: LANE, gap: GAP }), BSS, 0),
                H.tok);
    var dpr = window.devicePixelRatio || 1, g = c.getContext("2d");
    g.font = 10 * dpr + "px " + H.css("--font-mono");
    g.textBaseline = "middle";
    names.forEach(function (n, k) {
      g.fillStyle = H.tok(lanes[k].token);
      g.fillText(n, 2 * dpr, (k * (LANE + GAP) + LANE / 2) * dpr);
    });
    return { max: glyph.g7Max(lanes), lanes: lanes.length, keys: keys };
  }

  window.SlothAir = { init: function (h) { H = h; }, horizon: horizon, drill: drill, rug: rug,
                      floodRug: floodRug, ROW: ROW };
})();
