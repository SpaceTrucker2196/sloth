// slothweb: G2 and G6 in the tables, and the new mark
// (docs/web-visual-spec.md F9, F15, F17, F20, §6.4 to §6.8; #171
// slice V2). The geometry is glyph.js's; this module puts it in a cell.
// window.SlothRf, the hooks app.js calls:
//   SlothRf.init(h)              once, main()'s helpers lent
//   SlothRf.cell(c, rf, dbm)     a DBM cell: G2, the number, sloth's words;
//                                true when sloth's trend says approaching
//   SlothRf.block(rf, mac)       the drawer's and the Lookup card's G2 at
//                                full width, its three time labels and
//                                its caption, as one node
//   SlothRf.bullet(c, v, o, t)   a bounded score as G6's bullet and t
//   SlothRf.count(c, v, max, t)  a count as G6's bar behind t
//   SlothRf.newMark(first, from) the F15 dot, or null
//   SlothRf.colMax(rows, f)      a column's largest value, for a shared
//                                count scale (R3)
// A canvas is painted once it is in the document (its width is the
// layout's): at once when it already is, else on the next frame, after
// the caller has appended its row. Values only ever reach textContent.
(function () {
  "use strict";
  var H = null;
  var Q = [];
  var queued = false;

  function num(v) { return typeof v === "number" && isFinite(v); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = String(text);
    return e;
  }
  function clear(c) { while (c.firstChild) c.removeChild(c.firstChild); }

  function flush() {
    queued = false;
    var q = Q;
    Q = [];
    for (var i = 0; i < q.length; i++) if (q[i][0].isConnected) draw(q[i][0], q[i][1]);
  }
  function draw(cv, marks) {
    glyph.paint(cv, marks(cv.clientWidth, cv.clientHeight), H.tok);
  }
  // marks(w, h) is the canvas's mark list at its laid-out size.
  function later(cv, marks) {
    if (cv.isConnected) { draw(cv, marks); return; }
    Q.push([cv, marks]);
    if (!queued) { queued = true; window.requestAnimationFrame(flush); }
  }

  // A row's "rf" (web/src/web_rf.h) as G2's points: [t, dBm] for each
  // minute cell with a value, t the cell's start; and its window.
  function pts(rf) {
    var out = [];
    if (!rf || !rf.cells) return out;
    for (var i = 0; i < rf.cells.length; i++)
      if (num(rf.cells[i])) out.push([rf.from + i * rf.cell_s, rf.cells[i]]);
    return out;
  }
  function span(rf) {
    var n = rf && rf.cells && rf.cells.length ? rf.cells.length : 60;
    var from = rf && num(rf.from) ? rf.from : 0, st = rf && rf.cell_s > 0 ? rf.cell_s : 60;
    return { from: from, to: from + n * st, step: st };
  }
  function g2Marks(rf, p) {
    var sp = span(rf);
    return function (w, h) {
      return glyph.g2(p, { w: w, h: h, from: sp.from, to: sp.to, step: sp.step,
                           whisker: rf ? rf.whisker : null });
    };
  }
  // The words of sloth's estimate for a title, in full.
  function estText(rf) {
    if (!rf || (!rf.band && !rf.trend)) return "no distance estimate from sloth";
    return "sloth's estimate: " + (rf.band || "no band") + ", " + (rf.trend || "trend unknown") +
           " (from its " + rf.est_src + " record; signal strength, not a location)";
  }

  // The DBM column (F9): G2 at 72 px on the fixed scale, the last
  // value written (R7), bold when sloth says approaching, and sloth's
  // band and trend glyph after it. A row with no trail (Local's, or a
  // slothweb with no series) is R5's dash and sloth.db's number. In a
  // table every row draws the same hour, so the rows compare (P4).
  function cell(c, rf, dbm) {
    clear(c);
    var p = pts(rf), last = p.length ? p[p.length - 1][1] : dbm;
    var w = glyph.g2Words(last, rf ? rf.band : null, rf ? rf.trend : null);
    var cv = el("canvas", "g2");
    c.appendChild(cv);
    c.appendChild(el("span", w.bold ? "g2n near" : "g2n", w.text));
    if (w.near) c.appendChild(el("span", "g2e", " " + w.near));
    c.title = (rf ? rf.metric + ", 1 h, fine, " + glyph.RSSI_LO + " to " + glyph.RSSI_HI +
               " dBm, n=" + (num(rf.n) ? rf.n : 0) : "no signal series") + "; " + estText(rf);
    later(cv, g2Marks(rf, p));
    return w.bold;
  }

  function hhmm(t) {
    var d = new Date(t * 1000);
    function two(n) { return (n < 10 ? "0" : "") + n; }
    return two(d.getHours()) + ":" + two(d.getMinutes());
  }

  // The drawer's and the Lookup card's G2 (F20, §6.8): full width, its
  // window's three time labels under it, and R9's caption with the
  // -67 dBm rule named for what it is (ruling 3) and sloth's words.
  // Here R4 holds: a trail covering under a tenth of the hour draws
  // the span it has, and the caption says so. With nothing to draw the
  // block is its caption alone (R5).
  function block(rf, mac) {
    var box = el("div", "g2b");
    box.appendChild(el("div", "label", "signal, the last hour"));
    if (!rf) {
      box.appendChild(el("div", "sub", "no signal series: rf.rssi.* are the monitor radio's, " +
                         "not shown under this scope, or this slothweb keeps no series"));
      return box;
    }
    var p = pts(rf), sp = span(rf), gw = glyph.win(p, sp.from, sp.to);
    if (!p.length) {
      box.appendChild(el("div", "sub", glyph.caption({ source: rf.metric + " " + mac,
        window: "1 h", tier: "fine", scale: glyph.RSSI_LO + " to " + glyph.RSSI_HI + " dBm",
        n: 0, state: "no data" }) + "; " + estText(rf)));
      return box;
    }
    var cv = el("canvas", "g2w");
    cv.ariaLabel = "signal strength over the last hour, " + glyph.RSSI_LO + " to " +
                   glyph.RSSI_HI + " dBm";
    box.appendChild(cv);
    var t = el("div", "g2t");
    t.appendChild(el("span", "", hhmm(gw.from)));
    t.appendChild(el("span", "", hhmm(Math.round((gw.from + gw.to) / 2))));
    t.appendChild(el("span", "", hhmm(gw.to)));
    box.appendChild(t);
    var w = glyph.g2Words(p[p.length - 1][1], rf.band, rf.trend);
    var cl = glyph.g2Clamped(p);
    var note = el("div", "sub");
    note.appendChild(el("span", w.bold ? "g2n near" : "g2n", w.text + " dBm"));
    note.appendChild(document.createTextNode((w.near ? " " + w.near : "") + "; " +
      glyph.caption({ source: rf.metric + " " + mac, window: "1 h",
        tier: "fine", scale: glyph.RSSI_LO + " to " + glyph.RSSI_HI + " dBm",
        n: rf.n, state: gw.shrunk ? gw.text : "" }) +
      (cl ? ", " + cl + " clamped" : "") + "; rule at " + glyph.RSSI_REF +
      " dBm, a field rule of thumb, not a standard" +
      (rf.whisker_src ? "; whisker: " + (rf.whisker_src === "beacon"
        ? "the beacon's 60 s range" : "the last minute's samples") : "") +
      "; " + estText(rf)));
    box.appendChild(note);
    later(cv, function (cw, ch) {
      return glyph.g2(p, { w: cw, h: ch, from: gw.from, to: gw.to, step: sp.step,
                           whisker: rf.whisker });
    });
    return box;
  }

  // F17: a bounded score as G6's bullet (risk, karma, the anomaly
  // score), its number after it in the class the caller gives.
  function bullet(c, v, o, text, cls) {
    clear(c);
    var cv = el("canvas", "g6");
    c.appendChild(cv);
    c.appendChild(el("span", cls || "", text));
    later(cv, function (w, h) {
      return glyph.g6(num(v) ? v : null, { w: w, h: h, max: o.max, ranges: o.ranges,
                                           threshold: o.threshold });
    });
  }
  // F17: a count in a column as G6's bar on the column's own maximum
  // (R3: one scale per column), the number kept.
  function count(c, v, max, text, cls) {
    clear(c);
    var cv = el("canvas", "g6");
    c.appendChild(cv);
    c.appendChild(el("span", cls || "", text));
    later(cv, function (w, h) {
      return glyph.g6(num(v) ? v : null, { w: w, h: h, max: max, count: true });
    });
  }
  function colMax(rows, f) {
    var m = 0;
    for (var i = 0; rows && i < rows.length; i++) {
      var v = f(rows[i]);
      if (num(v) && v > m) m = v;
    }
    return m;
  }

  // F15: the --signal dot before a row's swatch, the one accent of the
  // row (P6), and a word in its title for a reader without the colour
  // (R10). null when the row is not new.
  function newMark(first, from) {
    if (!glyph.isNew(first, from)) return null;
    var d = el("span", "nw");
    d.title = "new: first seen in the last 24 h";
    return d;
  }

  window.SlothRf = { init: function (h) { H = h; }, cell: cell, block: block, bullet: bullet,
                     count: count, colMax: colMax, newMark: newMark, pts: pts };
})();
