// slothweb: every key of a metric on the Activity page's one graph
// (owner request and ruling of 2026-11-11, "keys: all"). The page's
// graph draws one key over its band; this draws them all, one line a
// key in the key's hash colour (the --k-0..7 the TUI gives an address,
// by the page's own ipColorIndex), on one shared y-scale, with a legend
// that lists every key drawn. R1's one ink is set aside for this mode
// by that ruling and for nothing else.
//
// Eight colours and up to 8,192 keys: colour is never the only carrier
// (R10). The legend is ranked and numbered, the top few lines carry
// their rank and key at their right end, and a legend entry hovered,
// focused or picked brings its line forward in its colour while every
// other line goes to --faint.
//
// Every key is every key (owner ruling 2026-11-11, "lift the cap"):
// /api/series/all walks them all, a page an answer, and this draws
// what has arrived while the rest is read, saying "loading N of M
// keys". What bounds it is said, never silent: the graph holds 8,192
// keys (--web-max-keys' own maximum) and a read stops at 60 s; past
// either the caption says "N of M keys" and why. The cells the graph
// holds across all its keys are bounded too (POINTS), so many keys are
// read at fewer cells each and the paint stays inside a frame.
//
// Two halves, as glyph.js: rank(), keysText(), tierOf(), colsFor(),
// filterRows(), lines(), frame() and strips() are pure (no DOM, no
// canvas, no theme) and are ported line for line into
// web/tests/test_allkeys.c, which pins them verbatim; the rest fetches,
// builds the legend and paints the list (paintMarks(), glyph.paint()'s
// rules with the lines batched). Keys are untrusted text: textContent,
// fillText and encodeURIComponent only.
//
// window.SlothAllKeys, two hooks app.js calls:
//   SlothAllKeys.init(h)   once, main()'s helpers lent
//   SlothAllKeys.main(m)   from mainChart(): true when the mode is on
//                          and this drew the graph for metric m
(function () {
  "use strict";
  var H = null;
  // R6 and R5, as glyph.js has them.
  var DOTS_BELOW = 5;
  var GAP_STEPS = 2.5;
  // The lines that carry their rank and key at their right end.
  var LABELS = 5;
  var LABEL_H = 10;
  var LABEL_GAP = 11;
  // The plot's insets: the y numbers, the end labels, the time labels.
  var PAD_L = 48, PAD_R = 132, PAD_T = 6, PAD_B = 16;
  // web_allkeys.h: WEB_ALLKEYS_COLS_MIN, _MAX and _BUCKETS.
  var COLS_MIN = 8, COLS_MAX = 480, BUCKETS = 10080;
  // The keys the graph holds: --web-max-keys' own maximum
  // (WEB_MAX_KEYS_MAX), so every key a rollup can hold is drawn.
  var KEYS_MAX = 8192;
  // The cells the graph holds across all its keys: 8,192 keys of 64
  // cells, 1,092 of the plot's 480. What a read carries and the page
  // keeps is bounded by it.
  var POINTS = 524288;
  // And for a presence metric, whose every cell can be a mark of its
  // own: 8,192 keys of 16 cells.
  var POINTS_STRIPS = 131072;
  // The keys drawn as lines: the largest LINES by the legend's order,
  // and the focus row whatever its rank. A line costs its length in
  // pixels to draw, so 8,192 of them are 8,192 plot widths however few
  // cells each has; past LINES the rest are drawn as one thing, the
  // range they span in each cell, which is what a mass of lines shows.
  var LINES = 256;
  // A read that has run this long stops, and the caption says so.
  var READ_MS = 60000;
  // While a first read runs, the graph is drawn again this often.
  var DRAW_MS = 300;
  // The legend's entries in the page at once; "show more" adds as many.
  var LEGEND_CHUNK = 200;
  // The line of a row that is not the focus: grey, a step above --rule.
  var DIM = "--faint";
  var S = { on: false, gen: 0, got: null, of: "", at: 0, pick: null, hot: null,
            scale: null, scaleOf: "", lastKey: null, ctx: "", rows: [], view: null,
            bl: null, blOf: "", raf: 0, m: null, shrunk: "", clamped: false,
            loading: false, done: false, took: 0, tick: 0, filter: "", shown: LEGEND_CHUNK,
            lkeys: [], pickOut: false };

  function gnum(v) { return typeof v === "number" && isFinite(v); }
  function $(id) { return document.getElementById(id); }

  // The legend's order, and so every other order here: the latest
  // value, largest first; a key with nothing in the window after every
  // key with something; equal values by the key's bytes. rows are
  // [{key, cur}], cur a number or null; the answer is a new array.
  function rank(rows) {
    var out = (rows || []).slice();
    out.sort(function (a, b) {
      var na = gnum(a.cur), nb = gnum(b.cur);
      if (na !== nb) return na ? -1 : 1;
      if (na && a.cur !== b.cur) return b.cur - a.cur;
      return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
    });
    return out;
  }

  // How many keys the graph holds, for the caption's source: all of
  // them, or "N of M" with the reason, never fewer in silence. cut is
  // "" for a whole read, "bound" for the graph's KEYS_MAX, "time" for
  // READ_MS, "stopped" for a read the server ended; min says the total
  // is a count the server stopped at; loading is a read under way.
  function keysText(shown, total, cut, min, loading) {
    var of = gnum(total) ? " of " + total + (min ? "+" : "") : "";
    if (loading) return "loading " + shown + of + " keys";
    if (cut === "bound") return shown + of + " keys, the first by key (the graph holds " + shown + ")";
    if (cut === "time") return shown + of + " keys (the read was stopped at 60 s)";
    if (cut === "stopped") return shown + of + " keys (the read stopped)";
    return shown + (shown === 1 ? " key" : " keys");
  }

  // The tier a window is read in: the finest whose buckets over the
  // window are within the route's bound (web_allkeys.h), so a key costs
  // at most 10,080 rows. Without a store there is only the fine tier,
  // and the window is its 24 h. [tier, step, window].
  function tierOf(win, storeOn) {
    if (!storeOn || win <= 86400) return ["fine", 10, win > 86400 ? 86400 : win];
    if (win <= BUCKETS * 60) return ["minute", 60, win];
    return ["hour", 3600, win > BUCKETS * 3600 ? BUCKETS * 3600 : win];
  }

  // The cells each key is read in: the plot's own (one for every two
  // pixels) while every key's cells together are within what the graph
  // holds, else as many as that leaves each key, never under the
  // route's least. total is how many keys there are (the graph holds
  // max of them).
  function colsFor(total, plot, points, max, least) {
    var n = total > max ? max : total;
    if (!(n > 0) || n * plot <= points) return plot;
    var c = Math.floor(points / n);
    return c < least ? least : c;
  }

  // The legend's filter: the rows whose key holds q, ASCII case aside;
  // every row for an empty q. The answer is the rows' indices, so an
  // entry keeps the rank it has among them all.
  function filterRows(rows, q) {
    var out = [], i;
    q = q.toLowerCase();
    for (i = 0; i < rows.length; i++)
      if (q === "" || rows[i].key.toLowerCase().indexOf(q) >= 0) out.push(i);
    return out;
  }

  // A presence row's height for n rows: 8 px (6 of ink, 2 of gap) while
  // the stack is within 4,096 px, then 4, 2 and 1, so 8,192 rows are a
  // canvas a browser will make. [row, ink, the rows between ranks].
  function stripRow(n) {
    if (n <= 512) return [8, 6, 5];
    if (n <= 1024) return [4, 2, 10];
    if (n <= 4096) return [2, 2, 50];
    return [1, 1, 100];
  }

  // The multi-key mark list. rows are in the legend's order, each
  // {k, pts, label}: k the key's colour index, pts [t, v] oldest first,
  // label its end-of-line words. opt: {w, h, padL, padR, padT, padB,
  // from, to, step, t0, scale, pick, hot, labels, lines, band}: scale
  // the shared [lo, hi]; pick and hot the picked and the hovered row or
  // -1; lines how many rows are drawn as lines, the rest folded into
  // one range a cell (the cells counted from t0 in steps); band
  // the picked row's, as G1 takes it, or null. Rows are listed last
  // first and the focus row (hot, else pick) after them all, so it is
  // drawn over the rest; with a focus every other row is DIM.
  function lines(rows, opt) {
    var m = [], w = opt.w, h = opt.h, i, j, n;
    var x0 = opt.padL, x1 = w - opt.padR, y0 = opt.padT, y1 = h - opt.padB;
    var any = false;
    for (i = 0; i < rows.length; i++) if (rows[i].pts.length) any = true;
    if (!any) { m.push(["dash", w * 0.35, h / 2, w * 0.3, 1, "--faint"]); return m; }
    var from = opt.from, to = opt.to, lo = opt.scale[0], hi = opt.scale[1];
    var X = function (t) { return to > from ? x0 + (t - from) / (to - from) * (x1 - x0) : x0; };
    var Y = function (v) { return y1 - (v - lo) / (hi - lo) * (y1 - y0); };
    var focus = opt.hot >= 0 ? opt.hot : opt.pick;
    var gap = opt.step * GAP_STEPS;
    var bp = opt.band && opt.pick >= 0 && opt.pick < rows.length ? rows[opt.pick].pts : null;
    for (i = 0; bp && i < bp.length; i++) {
      var b = opt.band[i];
      if (!b) continue;
      var bx = X(bp[i][0]);
      var bw = Math.min(Math.max(1, X(bp[i][0] + opt.step) - bx), Math.max(0, x1 - bx));
      if (bw > 0) m.push(["band", bx, Y(b[1]), bw, Y(b[0]) - Y(b[1]), "--data"]);
    }
    // The rows past opt.lines, but the focus: the least and the most of
    // them in each cell, one range mark a cell, under every line.
    var rl = [], rh = [], c, p;
    for (i = opt.lines; i < rows.length; i++) {
      if (i === focus) continue;
      p = rows[i].pts;
      for (j = 0; j < p.length; j++) {
        c = Math.round((p[j][0] - opt.t0) / opt.step);
        if (c < 0) continue;
        if (rl[c] === undefined || p[j][1] < rl[c]) rl[c] = p[j][1];
        if (rh[c] === undefined || p[j][1] > rh[c]) rh[c] = p[j][1];
      }
    }
    for (c = 0; c < rl.length; c++) {
      if (rl[c] === undefined) continue;
      var ex = X(opt.t0 + c * opt.step);
      var ew = Math.min(Math.max(1, X(opt.t0 + (c + 1) * opt.step) - ex), Math.max(0, x1 - ex));
      if (ew > 0 && ex >= x0) m.push(["range", ex, Y(rh[c]), ew, Math.max(1, Y(rl[c]) - Y(rh[c])), DIM]);
    }
    for (n = rows.length < opt.lines ? rows.length : opt.lines; n >= 0; n--) {
      i = n > 0 ? n - 1 : focus;
      if (i < 0 || (n > 0 && i === focus)) continue;
      p = rows[i].pts;
      if (!p.length) continue;
      var tok = focus >= 0 && i !== focus ? DIM : "--k-" + rows[i].k;
      var dots = p.length < DOTS_BELOW;
      for (j = 0; j < p.length; j++) {
        var left = j > 0 && p[j][0] - p[j - 1][0] <= gap;
        var right = j + 1 < p.length && p[j + 1][0] - p[j][0] <= gap;
        if (j > 0 && !left)
          m.push(["gap", X(p[j - 1][0]), y0, X(p[j][0]) - X(p[j - 1][0]), y1 - y0, "--faint"]);
        if (left && !dots)
          m.push(["line", X(p[j - 1][0]), Y(p[j - 1][1]), X(p[j][0]) - X(p[j - 1][0]),
                  Y(p[j][1]) - Y(p[j - 1][1]), tok]);
        // A point no line reaches is a dot, or it would not be drawn.
        if ((dots || (!left && !right)) && j < p.length - 1)
          m.push(["dot", X(p[j][0]), Y(p[j][1]), 1.5, 1.5, tok]);
      }
      m.push(["last", X(p[p.length - 1][0]), Y(p[p.length - 1][1]), 2.5, 2.5, tok]);
    }
    // The end labels: the first opt.labels rows that have a point, and
    // the focus row whatever its rank; pushed apart top down, then the
    // stack lifted back inside the plot.
    var li = [], ly = [], lc = 0;
    for (i = 0; i < rows.length && opt.padR > 8; i++) {
      if (!rows[i].pts.length) continue;
      if (lc >= opt.labels && i !== focus) continue;
      lc++;
      var y = Y(rows[i].pts[rows[i].pts.length - 1][1]);
      for (j = li.length; j > 0 && ly[j - 1] > y; j--) { li[j] = li[j - 1]; ly[j] = ly[j - 1]; }
      li[j] = i;
      ly[j] = y;
    }
    for (j = 1; j < li.length; j++) if (ly[j] < ly[j - 1] + LABEL_GAP) ly[j] = ly[j - 1] + LABEL_GAP;
    var over = li.length ? ly[li.length - 1] - (y1 - LABEL_H / 2) : 0;
    for (j = 0; j < li.length; j++)
      m.push(["label", x1 + 6, over > 0 ? ly[j] - over : ly[j], opt.padR - 8, LABEL_H,
              focus >= 0 && li[j] !== focus ? DIM : "--k-" + rows[li[j]].k, rows[li[j]].label]);
    return m;
  }

  // The plot's frame, drawn under the lines: the scale's top and bottom
  // as two --rule hairlines with their numbers, three time labels and
  // the now mark (R4), the panel's one --signal. opt as lines() takes
  // it, with ytop and ybot the scale's two numbers as words, xt the
  // three times as words, and now.
  function frame(opt) {
    var m = [], w = opt.w, h = opt.h;
    var x0 = opt.padL, x1 = w - opt.padR, y0 = opt.padT, y1 = h - opt.padB;
    m.push(["axis", x0, y0, x1 - x0, 1, "--rule"]);
    m.push(["axis", x0, y1, x1 - x0, 1, "--rule"]);
    m.push(["num", 2, y0 + 5, x0 - 6, 10, "--muted", opt.ytop]);
    m.push(["num", 2, y1 - 5, x0 - 6, 10, "--muted", opt.ybot]);
    m.push(["num", x0, h - 6, 96, 10, "--muted", opt.xt[0]]);
    m.push(["num", (x0 + x1) / 2 - 24, h - 6, 96, 10, "--muted", opt.xt[1]]);
    m.push(["num", x1 - 48, h - 6, 96, 10, "--muted", opt.xt[2]]);
    if (opt.to > opt.from && opt.now >= opt.from && opt.now <= opt.to)
      m.push(["now", x0 + (opt.now - opt.from) / (opt.to - opt.from) * (x1 - x0), y0, 1, y1 - y0, "--signal"]);
    return m;
  }

  // A presence metric has no line: its keys are stacked strips, one row
  // a key in the legend's order, each run of cells the key was present
  // in one mark in the key's colour. rows are [{k, cells}], cells the
  // present cells' indices ascending. opt: {w, rowH, ink, every, padL,
  // padR, ncell, pick, hot, xt}: a row is rowH px, ink of them drawn
  // (stripRow()). The first row and every opt.every'th carry their
  // rank; under the last row, the window's three times (xt).
  function strips(rows, opt) {
    var m = [], x0 = opt.padL, pw = opt.w - opt.padL - opt.padR, rh = opt.rowH, i, j;
    var any = false;
    for (i = 0; i < rows.length; i++) if (rows[i].cells.length) any = true;
    if (!any) {
      m.push(["dash", opt.w * 0.35, Math.max(1, rows.length) * rh / 2, opt.w * 0.3, 1, "--faint"]);
      return m;
    }
    var focus = opt.hot >= 0 ? opt.hot : opt.pick;
    for (i = 0; i < rows.length; i++) {
      var c = rows[i].cells, y = i * rh;
      var tok = focus >= 0 && i !== focus ? DIM : "--k-" + rows[i].k;
      if (i === 0 || (i + 1) % opt.every === 0)
        m.push(["num", 2, y + rh / 2, x0 - 4, 8, "--muted", String(i + 1)]);
      for (j = 0; j < c.length; j++) {
        var a = c[j], e = a;
        while (j + 1 < c.length && c[j + 1] === e + 1) { j++; e++; }
        m.push(["cell", x0 + a / opt.ncell * pw, y, Math.max(1, (e + 1 - a) / opt.ncell * pw), opt.ink, tok]);
      }
    }
    var ty = rows.length * rh + 8;
    m.push(["num", x0, ty, 96, 10, "--muted", opt.xt[0]]);
    m.push(["num", x0 + pw / 2 - 24, ty, 96, 10, "--muted", opt.xt[1]]);
    m.push(["num", x0 + pw - 48, ty, 96, 10, "--muted", opt.xt[2]]);
    return m;
  }

  // ── the page's half ───────────────────────────────────────────────
  // This mode's painter: glyph.paint()'s rules for the kinds these mark
  // lists hold, with one difference that is only cost. A run of line
  // marks in one token is one path and one stroke, where glyph.paint()
  // strokes each segment: 256 keys of 480 cells are 122,880 segments.
  // (One path a row, not one a colour: a path of every row of a colour
  // was measured slower, not faster.) A range is the band's rectangle at
  // 35 percent. A gap draws nothing (R5).
  function paintMarks(c, marks, resolve) {
    var dpr = window.devicePixelRatio || 1;
    var w = Math.max(1, Math.round(c.clientWidth * dpr));
    var h = Math.max(1, Math.round(c.clientHeight * dpr));
    if (c.width !== w) c.width = w;
    if (c.height !== h) c.height = h;
    var g = c.getContext("2d"), open = null;
    g.clearRect(0, 0, w, h);
    g.lineWidth = Math.max(1, dpr);
    for (var i = 0; i < marks.length; i++) {
      var m = marks[i], k = m[0];
      if (k === "gap") continue;
      if (k === "line") {
        if (open !== m[5]) {
          if (open !== null) g.stroke();
          open = m[5];
          g.strokeStyle = resolve(open);
          g.beginPath();
        }
        g.moveTo(m[1] * dpr, m[2] * dpr);
        g.lineTo((m[1] + m[3]) * dpr, (m[2] + m[4]) * dpr);
        continue;
      }
      if (open !== null) { g.stroke(); open = null; }
      g.fillStyle = resolve(m[5]);
      if (typeof m[6] === "string") {
        g.font = Math.round(m[4] * dpr) + "px " + resolve("--font-mono");
        g.textBaseline = "middle";
        g.textAlign = "left";
        g.fillText(m[6], m[1] * dpr, m[2] * dpr, Math.max(1, m[3] * dpr));
      } else if (k === "band" || k === "range") {
        g.globalAlpha = k === "band" ? 0.12 : 0.35;
        g.fillRect(m[1] * dpr, m[2] * dpr, Math.max(1, m[3] * dpr), Math.max(1, m[4] * dpr));
        g.globalAlpha = 1;
      } else if (k === "dot" || k === "last") {
        g.beginPath();
        g.arc(m[1] * dpr, m[2] * dpr, Math.max(1, m[3] * dpr), 0, 6.283185307179586);
        g.fill();
      } else {
        g.fillRect(m[1] * dpr, m[2] * dpr, Math.max(1, m[3] * dpr), Math.max(1, m[4] * dpr));
      }
    }
    if (open !== null) g.stroke();
  }

  function modeBtn() {
    $("ak-mode").ariaPressed = S.on ? "true" : "false";
    H.set("ak-mode", S.on ? "keys: all" : "keys: one");
  }

  // One key's answer as a row: its points, its present cells, its
  // latest value. A presence key's value is the cells it was present
  // in, which is what its strip shows.
  function rowOf(k, head, presence) {
    var pts = [], cells = [], p = k.p;
    for (var i = 0; i + 1 < p.length; i += 2) {
      if (!gnum(p[i]) || !gnum(p[i + 1])) continue;
      pts.push([head.from + p[i] * head.cell, p[i + 1]]);
      if (p[i + 1] >= 0.5) cells.push(p[i]);
    }
    return { key: k.key, k: H.colorIndex(k.key), pts: pts, cells: cells, band: null,
             cur: presence ? (cells.length ? cells.length : null)
                           : pts.length ? pts[pts.length - 1][1] : null };
  }

  function indexOfKey(key) {
    if (key === null) return -1;
    for (var i = 0; i < S.rows.length; i++) if (S.rows[i].key === key) return i;
    return -1;
  }

  // The picked key's baseline, read once a key and a scope and kept
  // (it moves once an hour at most); the graph is drawn without its
  // band first and again when it arrives.
  function wantBand(m) {
    if (indexOfKey(S.pick) < 0 || !S.got || S.got.head.kind === "presence") return;
    var of = m.name + "\u0000" + S.pick + "\u0000" + H.scope();
    if (S.blOf === of) return;
    S.blOf = of;
    S.bl = null;
    H.baseline(m.name, S.pick).then(function (bl) {
      if (S.blOf !== of) return;
      S.bl = bl;
      paint(m);
    });
  }

  // The legend: every key drawn, ranked. Only LEGEND_CHUNK entries are
  // in the page at once (8,192 buttons would not be a list anyone
  // reads, and would cost a second to build): the filter narrows them
  // by the key's text, "show more" adds a chunk. An entry keeps the
  // rank it has among every key, filtered or not.
  function legend(m) {
    var box = $("ak-legend"), head = S.got ? S.got.head : null;
    var presence = !!head && head.kind === "presence";
    var hits = filterRows(S.rows, S.filter), n = Math.min(hits.length, S.shown);
    while (box.firstChild) box.removeChild(box.firstChild);
    S.lkeys = [];
    hits.slice(0, n).forEach(function (i) {
      var r = S.rows[i];
      var row = H.el("div", "ak-row");
      row.role = "listitem";
      var b = H.el("button", "ak-key" + (S.pick === r.key ? " on" : ""));
      b.type = "button";
      b.ariaPressed = S.pick === r.key ? "true" : "false";
      b.title = "show this key alone in its colour, the rest grey; again for every key";
      b.appendChild(H.el("span", "ak-rank", String(i + 1)));
      var sw = H.el("span", "sw");
      sw.style.background = "var(--k-" + r.k + ")";
      b.appendChild(sw);
      b.appendChild(r.key ? H.keySpan(r.key) : H.el("span", "d-normal", "(global)"));
      b.appendChild(H.el("span", "ak-v", r.cur === null ? "-"
        : presence ? r.cur + "/" + head.cells + " cells"
        : H.fmt(r.cur) + " " + m.unit));
      b.addEventListener("click", function () { pick(m, S.pick === r.key ? null : r.key); });
      b.addEventListener("mouseenter", function () { hot(m, r.key); });
      b.addEventListener("mouseleave", function () { hot(m, null); });
      b.addEventListener("focus", function () { hot(m, r.key); });
      b.addEventListener("blur", function () { hot(m, null); });
      row.appendChild(b);
      // A device has a drawer: the page's own way into it.
      if (H.isMac(r.key)) {
        var o = H.el("button", "dt-reset ak-open", "device");
        o.type = "button";
        o.title = "open this device";
        o.addEventListener("click", function () { H.openDrawer(r.key); });
        row.appendChild(o);
      }
      box.appendChild(row);
      S.lkeys.push(r.key);
    });
    $("ak-all").hidden = S.pick === null;
    $("ak-filter").hidden = S.rows.length <= 8 && S.filter === "";
    $("ak-more").hidden = n >= hits.length;
    H.set("ak-more", "show " + Math.min(LEGEND_CHUNK, hits.length - n) + " more");
    H.set("ak-rule", !S.rows.length ? ""
      : (presence ? "every key by the cells it was present in, most first"
                  : "every key by its latest value, largest first") +
        "; equal values by key. Pick one to show it alone; Esc or the same entry again for all." +
        (n < S.rows.length ? " Listed: " + n + " of " +
          (S.filter === "" ? S.rows.length : hits.length + " matching, of " + S.rows.length) + "."
                           : ""));
  }

  function pick(m, key) {
    S.pick = key;
    // The key picker follows, when the key is one of its 256.
    S.pickOut = false;
    if (key !== null) { S.pickOut = !H.pickKey(key); S.lastKey = H.key(); }
    var bs = $("ak-legend").querySelectorAll("button.ak-key");
    for (var i = 0; i < bs.length && i < S.lkeys.length; i++) {
      var on = S.lkeys[i] === key;
      bs[i].classList.toggle("on", on);
      bs[i].ariaPressed = on ? "true" : "false";
    }
    $("ak-all").hidden = key === null;
    wantBand(m);
    paint(m);
  }

  // A hover or a focus repaints at most once a frame.
  function hot(m, key) {
    if (S.hot === key) return;
    S.hot = key;
    if (S.raf) return;
    S.raf = window.requestAnimationFrame(function () { S.raf = 0; paint(m); });
  }

  function stamp(t, win) {
    if (win <= 86400) return H.hhmmss(t).slice(0, 5);
    var d = new Date(t * 1000);
    function two(n) { return (n < 10 ? "0" : "") + n; }
    return two(d.getMonth() + 1) + "-" + two(d.getDate()) + " " + two(d.getHours()) + ":00";
  }

  function isBanded(band) {
    for (var i = 0; band && i < band.length; i++) if (band[i]) return true;
    return false;
  }

  // The graph and its caption, from what was last read.
  function paint(m) {
    var g = S.got;
    if (!S.on || !g) return;
    var head = g.head, cv = $("ak-chart"), presence = head.kind === "presence";
    var pi = indexOfKey(S.pick), hi = indexOfKey(S.hot), pn = 0, i;
    // The band is the picked key's alone, at the slider's k as it is now.
    var band = pi >= 0 && !presence && S.bl && S.blOf === m.name + "\u0000" + S.pick + "\u0000" + H.scope()
      ? H.bands(S.rows[pi].pts, S.bl, head.kind, head.cell) : null;
    // R5: an empty panel collapses to its caption.
    cv.hidden = !S.rows.length;
    for (i = 0; i < S.rows.length; i++) pn += S.rows[i].pts.length;
    var win = head.to - head.from, marks, scaleText;
    var keys = keysText(S.rows.length, g.total, g.cut, g.min, S.loading && !S.done);
    if (presence) {
      var sr = stripRow(S.rows.length);
      cv.style.height = Math.max(3, S.rows.length) * sr[0] + PAD_B + "px";
      var so = { w: cv.clientWidth, rowH: sr[0], ink: sr[1], every: sr[2], padL: 28, padR: 4,
                 ncell: head.cells, pick: pi, hot: hi,
                 xt: [stamp(head.from, win), stamp((head.from + head.to) / 2, win), stamp(head.to, win)] };
      marks = strips(S.rows, so);
      S.view = { presence: true, o: so };
      scaleText = pn ? "0/1, one row a key, sorted by cells present" : "";
    } else {
      cv.style.height = "";
      // R11: the shared scale grows and never shrinks on a refresh; a
      // new metric, scope or window starts it again. R4: a window the
      // data covers under a tenth of is drawn as the data's own.
      var lo = 0, hi2 = 0, t0 = null, t1 = null;
      var sc = glyph.shared(S.rows, S.scaleOf === S.of ? S.scale : null);
      if (band) sc = glyph.scale(S.rows[pi].pts, band, sc);
      S.scale = sc;
      S.scaleOf = S.of;
      lo = sc[0];
      hi2 = sc[1];
      for (i = 0; i < S.rows.length; i++) {
        var p = S.rows[i].pts;
        if (!p.length) continue;
        if (t0 === null || p[0][0] < t0) t0 = p[0][0];
        if (t1 === null || p[p.length - 1][0] > t1) t1 = p[p.length - 1][0];
      }
      var gw = glyph.win(t0 === null ? [] : [[t0, 0], [t1, 0]], head.from, head.to);
      var o = { w: cv.clientWidth, h: cv.clientHeight, padL: PAD_L, padR: PAD_R, padT: PAD_T, padB: PAD_B,
                from: gw.from, to: gw.to, step: head.cell, t0: head.from, scale: [lo, hi2], pick: pi, hot: hi,
                labels: LABELS, lines: LINES, band: band, now: Date.now() / 1000,
                ytop: H.fmt(hi2), ybot: H.fmt(lo),
                xt: [stamp(gw.from, win), stamp((gw.from + gw.to) / 2, win), stamp(gw.to, win)] };
      for (i = 0; i < S.rows.length; i++)
        S.rows[i].label = (i + 1) + " " + (S.rows[i].key || "(global)");
      marks = frame(o).concat(lines(S.rows, o));
      S.view = { presence: false, o: o };
      var banded = isBanded(band);
      scaleText = !pn ? "" : "shared scale, top " + H.fmt(hi2) + " " + m.unit + ", " +
        (banded ? "band ±" + H.sens().toFixed(1) + " sd for " + S.pick
                : pi >= 0 ? "no band for " + S.pick + " yet"
                : "no band: it is one key's, pick a key for its") +
        ", sorted by latest value" +
        (S.rows.length > LINES ? ", lines for the " + LINES + " largest, the other " +
                                 (S.rows.length - LINES) + " as their range a cell" : "");
      S.shrunk = gw.shrunk ? gw.text : "";
    }
    paintMarks(cv, marks, H.tok);
    var cellWord = head.cell === head.step ? head.tier
      : head.tier + " in " + glyph.dur(head.cell) + " cells (" +
        (head.kind === "counter" ? "sum" : head.kind === "presence" ? "any" : "mean") + ")";
    H.set("a-title", m.name + "  every key  (" + m.unit + ")");
    H.set("a-src", glyph.caption({
      source: m.name + ", " + keys + ", " + head.source,
      window: glyph.dur(win), tier: cellWord, scale: scaleText, n: pn,
      state: head.out_of_scope === true ? "not in the " + H.scopeWord(H.scope()) + " scope"
           : !S.rows.length ? (S.loading && !S.done ? "" : "no " + (head.keykind || "key") + " seen yet")
           : !pn ? "no data"
           : !presence && S.shrunk ? S.shrunk
           : !presence && pi >= 0 && !isBanded(band) ? "warming" : "" }) +
      (S.pickOut && S.pick !== null ? "; " + S.pick + " is not one of the key picker's 256" : "") +
      (S.clamped ? "; minute and hour tiers need a WITH_SQLITE build" : ""));
  }

  // The row under the pointer: a presence row by its place, a line by
  // the nearest value at the pointer's time. -1 for none.
  function rowAt(x, y) {
    var v = S.view, i;
    if (!v) return -1;
    if (v.presence) {
      i = Math.floor(y / v.o.rowH);
      return i >= 0 && i < S.rows.length ? i : -1;
    }
    var o = v.o, x0 = o.padL, x1 = o.w - o.padR, y0 = o.padT, y1 = o.h - o.padB;
    if (x < x0 || x > x1 || !(o.to > o.from)) return -1;
    var t = o.from + (x - x0) / (x1 - x0) * (o.to - o.from), best = -1, bd = 12;
    for (i = 0; i < S.rows.length; i++) {
      var p = S.rows[i].pts, a = 0, b = p.length - 1;
      // A row folded into the range has no line to point at.
      if (!p.length || (i >= o.lines && i !== o.pick)) continue;
      while (a < b) { var mid = (a + b) >> 1; if (p[mid][0] < t) a = mid + 1; else b = mid; }
      if (a > 0 && t - p[a - 1][0] < p[a][0] - t) a--;
      if (Math.abs(p[a][0] - t) > o.step * GAP_STEPS) continue;
      var d = Math.abs(y1 - (p[a][1] - o.scale[0]) / (o.scale[1] - o.scale[0]) * (y1 - y0) - y);
      if (d < bd) { bd = d; best = i; }
    }
    return best;
  }

  // One answer's keys as rows, onto the read's own list.
  function take(R, j) {
    var ks = j.keys || [], presence = R.head.kind === "presence";
    for (var i = 0; i < ks.length && R.rows.length < KEYS_MAX; i++)
      if (ks[i] && typeof ks[i].key === "string" && Array.isArray(ks[i].p))
        R.rows.push(rowOf(ks[i], R.head, presence));
  }

  // What a read has so far, onto the page: ranked, listed, drawn. done
  // is the read's end, with why it ended short ("" when it did not).
  function land(m, R, done, cut) {
    S.got = { head: R.head, total: R.total, min: R.min, cut: cut };
    S.rows = rank(R.rows);
    S.done = done;
    if (done) {
      S.loading = false;
      S.at = Date.now();
      S.took = S.at - R.t0;
    }
    if (indexOfKey(S.pick) < 0) { S.pick = null; S.pickOut = false; }
    S.hot = null;
    legend(m);
    wantBand(m);
    paint(m);
  }

  // Read the window again when it, the metric or the scope changed, or
  // when a cell's time has passed (60 s at most, and never sooner than
  // ten times what the last read took: 8,192 keys are not read every
  // minute); between those a call only repaints.
  //
  // The read is a walk of /api/series/all's pages, one request at a
  // time, each answer handled in its own turn so the page stays
  // responsive. A first read of a window draws what has arrived every
  // DRAW_MS and says "loading N of M keys"; a later read of the same
  // window lands whole, so the graph does not flicker each minute. It
  // ends early, and says why, at KEYS_MAX keys or READ_MS. It stops
  // without a word when the metric, scope, window or mode changed
  // (S.gen moved) or the Activity view is no longer the one shown; the
  // next call starts it afresh.
  function load(m) {
    var want = Number($("a-win").value) || 3600;
    var tr = tierOf(want, H.storeOn()), tier = tr[0], step = tr[1], win = tr[2];
    // A cell for every two pixels of the plot: the box's width, because
    // the canvas is hidden while there is no key to draw.
    var plot = Math.max(COLS_MIN, Math.min(COLS_MAX, Math.floor(($("ak-box").clientWidth - PAD_L - PAD_R) / 2)));
    var of = m.name + "\u0000" + H.scope() + "\u0000" + win + "\u0000" + tier + "\u0000" + plot;
    if (S.loading && S.of === of) { paint(m); return; }
    var every = S.got ? Math.max(Math.min(60, S.got.head.cell) * 1000 - 500, S.took * 10) : 0;
    if (S.got && S.done && S.of === of && Date.now() - S.at < every) { paint(m); return; }
    var now = Math.floor(Date.now() / 1000);
    var to = now - now % step + step, from = to - win;
    var gen = ++S.gen, first = S.of !== of || !S.done;
    var R = { rows: [], head: null, total: null, min: false, cols: plot, t0: Date.now(), drawn: 0 };
    if (first) {
      S.got = null;
      S.rows = [];
      S.done = false;
      S.shown = LEGEND_CHUNK;
      legend(m);
      H.set("a-title", m.name + "  every key  (" + m.unit + ")");
      H.set("a-src", m.name + ", " + keysText(0, null, "", false, true));
    }
    S.of = of;
    S.loading = true;
    S.clamped = !H.storeOn() && want > 86400;
    function page(after) {
      var p = "/api/series/all?metric=" + encodeURIComponent(m.name) + "&tier=" + tier +
              "&from=" + from + "&to=" + to + "&cols=" + R.cols;
      if (after !== null) p += "&after=" + encodeURIComponent(after);
      return H.getJSON(p).then(function (j) {
        if (gen !== S.gen) return;
        if (!S.on || !H.active()) { S.gen++; S.loading = false; S.done = false; return; }
        if (after === null) {
          R.total = gnum(j.total) ? j.total : null;
          R.min = j.total_min === true;
          // More cells than the graph holds: the same walk at fewer
          // cells a key, from the start.
          var fit = colsFor(R.total === null ? 0 : R.total, R.cols,
                            j.kind === "presence" ? POINTS_STRIPS : POINTS, KEYS_MAX, COLS_MIN);
          if (fit < R.cols) { R.cols = fit; return page(null); }
        }
        R.head = j;
        take(R, j);
        var more = j.more === true && typeof j.next === "string";
        var cut = R.rows.length >= KEYS_MAX && j.more === true ? "bound"
                : more && Date.now() - R.t0 >= READ_MS ? "time"
                : j.more === true && !more ? "stopped" : "";
        if (!more || cut !== "") { land(m, R, true, cut); return; }
        if (first && Date.now() - R.drawn >= DRAW_MS) { R.drawn = Date.now(); land(m, R, false, ""); }
        return page(j.next);
      });
    }
    page(null).catch(function (e) {
      if (gen !== S.gen) return;
      S.loading = false;
      H.set("a-src", "error: " + e.message);
    });
  }

  function main(m) {
    $("ak-box").hidden = !S.on;
    $("a-chart").hidden = S.on;
    $("a-hover").hidden = S.on;
    if (!m) return false;
    // The key picker moved, on the same metric and scope: that key is
    // the one picked here. Another metric or scope starts with them all.
    var k = H.key(), ctx = m.name + "\u0000" + H.scope();
    if (ctx !== S.ctx) S.pick = null;
    else if (k !== S.lastKey && k !== "") S.pick = S.on ? k : null;
    if (k !== S.lastKey || ctx !== S.ctx) S.pickOut = false;
    S.ctx = ctx;
    S.lastKey = k;
    S.m = m;
    if (!S.on) return false;
    load(m);
    return true;
  }

  function init(h) {
    H = h;
    S.on = H.prefGet("act.allkeys") === true;
    modeBtn();
    $("ak-mode").addEventListener("click", function () {
      S.on = !S.on;
      H.prefSet("act.allkeys", S.on ? true : null);
      modeBtn();
      S.gen++;
      S.loading = false;
      if (!S.done) S.of = "";
      H.redraw();
    });
    $("ak-all").addEventListener("click", function () { if (S.m) pick(S.m, null); });
    $("ak-filter").addEventListener("input", function () {
      S.filter = $("ak-filter").value.trim();
      S.shown = LEGEND_CHUNK;
      if (S.m) legend(S.m);
    });
    $("ak-more").addEventListener("click", function () {
      S.shown += LEGEND_CHUNK;
      if (S.m) legend(S.m);
    });
    $("ak-legend").addEventListener("keydown", function (e) {
      if (e.key === "Escape" && S.m && S.pick !== null) pick(S.m, null);
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
      var bs = $("ak-legend").querySelectorAll("button.ak-key");
      for (var i = 0; i < bs.length; i++) {
        if (bs[i] !== document.activeElement) continue;
        var n = bs[i + (e.key === "ArrowDown" ? 1 : -1)];
        if (n) { e.preventDefault(); n.focus(); }
        return;
      }
    });
    var cv = $("ak-chart");
    cv.addEventListener("mousemove", function (e) {
      if (!S.m) return;
      var r = cv.getBoundingClientRect(), i = rowAt(e.clientX - r.left, e.clientY - r.top);
      var row = i >= 0 ? S.rows[i] : null;
      hot(S.m, row ? row.key : null);
      H.set("ak-hover", !row ? "" : (i + 1) + "  " + (row.key || "(global)") + "  " +
        (row.cur === null ? "-" : S.view.presence ? row.cur + "/" + S.got.head.cells + " cells present"
                                                  : "latest " + H.fmt(row.cur) + " " + S.m.unit));
    });
    cv.addEventListener("mouseleave", function () { if (S.m) hot(S.m, null); H.set("ak-hover", ""); });
    cv.addEventListener("click", function (e) {
      if (!S.m) return;
      var r = cv.getBoundingClientRect(), i = rowAt(e.clientX - r.left, e.clientY - r.top);
      if (i >= 0) pick(S.m, S.pick === S.rows[i].key ? null : S.rows[i].key);
    });
  }

  window.SlothAllKeys = { init: init, main: main, rank: rank, keysText: keysText, tierOf: tierOf,
                          colsFor: colsFor, filterRows: filterRows, stripRow: stripRow,
                          lines: lines, frame: frame, strips: strips,
                          paintMarks: paintMarks };
})();
