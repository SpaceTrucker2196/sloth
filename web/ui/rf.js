// slothweb: the S-meter and G6 in the tables, and the new mark
// (docs/web-visual-spec.md F9, F15, F17, F20, §6.4 to §6.8; #171
// slice V2). The geometry is glyph.js's; this module puts it in a cell.
// window.SlothRf, the hooks app.js calls:
//   SlothRf.init(h)              once, main()'s helpers lent
//   SlothRf.cell(c, rf, dbm, ch) a DBM cell: the S-meter (it replaced G2's
//                                sparkline, owner ruling 2026-11-11), its S
//                                reading, the number, sloth's words; ch the
//                                row's channel when it has one; true when
//                                sloth's trend says approaching
//   SlothRf.block(rf, mac, ch)   the drawer's and the Lookup card's meter
//                                at full width, its legend and its
//                                caption, as one node
//   SlothRf.meter(c, v, o, say)  a meter of any strength into a cell: o is
//                                {scale, lo, hi}, say its words for a
//                                reader without the picture
//   SlothRf.legend()             the meter's face and scale in words, once
//                                per table
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
  // The meter's marks for a latest reading and its window's range r
  // ([lo, hi] or null) on scale sc.
  function smMarks(v, sc, r) {
    return function (w, h) {
      return glyph.sm(num(v) ? v : null, { w: w, h: h, scale: sc, lo: r ? r[0] : null,
                                           hi: r ? r[1] : null });
    };
  }
  // The scale a reading was read on, for a title: the band's S9, and
  // that the band is not known when the row names none.
  function scaleText(sc) {
    return "S-meter, " + (sc.unknown ? "band unknown: 2.4 GHz scale" : sc.band + " scale") +
           ", S9 = " + glyph.SM_BANDS[sc.band].s9 + " dBm";
  }
  // The meter in words (the canvas's label): the reading, and how far
  // the window moved.
  function say(v, sc, r) {
    if (!num(v)) return "signal strength: no reading";
    return "signal strength " + glyph.smWord(v, sc) + ", " + Math.round(v) + " dBm" +
           (r && r[1] > r[0] ? "; over the last hour from " + glyph.smWord(r[0], sc) + " to " +
                               glyph.smWord(r[1], sc) + ", " + Math.round(r[0]) + " to " +
                               Math.round(r[1]) + " dBm" : "") +
           (sc.unknown ? "; band unknown: 2.4 GHz scale" : "; " + sc.band + " scale");
  }
  // A meter into a cell, for a module with a strength of its own (GNSS
  // C/N0, ADS-B dBFS): the table meter's size, the caller's scale and
  // words.
  function meter(c, v, o, words) {
    var cv = el("canvas", "g2");
    cv.role = "img";
    cv.ariaLabel = words;
    c.appendChild(cv);
    later(cv, smMarks(v, o.scale, num(o.lo) && num(o.hi) ? [o.lo, o.hi] : null));
    return cv;
  }
  // The face drawn once per table, as text so it follows the theme and
  // copies: a block a segment with its label, the run over S9 in the
  // peak heat class and after a gap, then every band's S9 in words.
  function legend() {
    var d = el("span", "smleg"), sc = glyph.smDbm(""), lab = glyph.smLabels(sc);
    d.appendChild(el("span", "d-dim", "S "));
    for (var i = 0; i < lab.length; i++)
      d.appendChild(el("span", i < sc.knee ? "d-normal" : "h3",
                       (i === sc.knee ? " " : "") + "\u2588" + lab[i] + " "));
    d.appendChild(el("span", "", glyph.smNote() + "; ticks: the hour's least and greatest"));
    return d;
  }
  // The words of sloth's estimate for a title, in full.
  function estText(rf) {
    if (!rf || (!rf.band && !rf.trend)) return "no distance estimate from sloth";
    return "sloth's estimate: " + (rf.band || "no band") + ", " + (rf.trend || "trend unknown") +
           " (from its " + rf.est_src + " record; signal strength, not a location)";
  }

  // The DBM column (F9): the S-meter at 72 px on its band's scale (the
  // band the row's "rf" names, web_rf.h "radio", else the row's channel
  // ch; a row with neither reads on the 2.4 GHz row and its title says
  // so), the S reading and the last value written (R7),
  // the number bold when sloth says approaching, and sloth's band and
  // trend glyph after it. The lit run is the last value and the two
  // ticks the hour's least and greatest. A row with no trail (Local's,
  // or a slothweb with no series) is sloth.db's number alone as the
  // run, and R5's dash with no number either. In a table every row
  // reads the same hour, so the rows compare (P4).
  function cell(c, rf, dbm, ch) {
    clear(c);
    var p = pts(rf), last = p.length ? p[p.length - 1][1] : dbm;
    var w = glyph.g2Words(last, rf ? rf.band : null, rf ? rf.trend : null);
    var sc = glyph.smDbm(glyph.smBand(ch, rf ? rf.radio : null)), r = glyph.smRange(p);
    var cv = el("canvas", "g2");
    cv.role = "img";
    cv.ariaLabel = say(last, sc, r);
    c.appendChild(cv);
    if (num(last)) c.appendChild(el("span", "sms", glyph.smWord(last, sc) + " "));
    c.appendChild(el("span", w.bold ? "g2n near" : "g2n", w.text));
    if (w.near) c.appendChild(el("span", "g2e", " " + w.near));
    c.title = (rf ? rf.metric + ", 1 h, fine, n=" + (num(rf.n) ? rf.n : 0) : "no signal series") +
              "; " + scaleText(sc) + "; " + estText(rf);
    later(cv, smMarks(last, sc, r));
    return w.bold;
  }

  // The drawer's and the Lookup card's meter (F20, §6.8): full width,
  // the face's legend under it, and R9's caption with the S reading,
  // the hour's range, the scale and sloth's words. Here R4 holds: a
  // trail covering under a tenth of the hour says the span it has.
  // With nothing to draw the block is its caption alone (R5). The
  // -67 dBm rule G2 drew is not on the meter: a third tick beside the
  // two peak-hold ticks does not read at this size.
  function block(rf, mac, ch) {
    var box = el("div", "g2b");
    box.appendChild(el("div", "label", "signal, the last hour"));
    if (!rf) {
      box.appendChild(el("div", "sub", "no signal series: rf.rssi.* are the monitor radio's, " +
                         "not shown under this scope, or this slothweb keeps no series"));
      return box;
    }
    var p = pts(rf), sp = span(rf), gw = glyph.win(p, sp.from, sp.to);
    var sc = glyph.smDbm(glyph.smBand(ch, rf ? rf.radio : null)), r = glyph.smRange(p);
    var scale = sc.lo + " to " + sc.hi + " dBm";
    if (!p.length) {
      box.appendChild(el("div", "sub", glyph.caption({ source: rf.metric + " " + mac,
        window: "1 h", tier: "fine", scale: scale,
        n: 0, state: "no data" }) + "; " + estText(rf)));
      return box;
    }
    var last = p[p.length - 1][1];
    var cv = el("canvas", "smw");
    cv.role = "img";
    cv.ariaLabel = say(last, sc, r);
    box.appendChild(cv);
    var w = glyph.g2Words(last, rf.band, rf.trend);
    var cl = glyph.smClamped(p, sc);
    var note = el("div", "sub");
    note.appendChild(el("span", "sms", glyph.smWord(last, sc) + " "));
    note.appendChild(el("span", w.bold ? "g2n near" : "g2n", w.text + " dBm"));
    note.appendChild(document.createTextNode((w.near ? " " + w.near : "") + "; " +
      (r[1] > r[0] ? "the hour " + glyph.smWord(r[0], sc) + " to " + glyph.smWord(r[1], sc) +
                     ", " + Math.round(r[0]) + " to " + Math.round(r[1]) + " dBm; " : "") +
      glyph.caption({ source: rf.metric + " " + mac, window: "1 h",
        tier: "fine", scale: scale,
        n: rf.n, state: gw.shrunk ? gw.text : "" }) +
      (cl ? ", " + cl + " clamped" : "") + "; " + scaleText(sc) +
      "; " + estText(rf)));
    box.appendChild(note);
    box.appendChild(el("div", "sub")).appendChild(legend());
    later(cv, smMarks(last, sc, r));
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

  // Every table with a meter column names its scale once: a .smkey
  // placeholder in the table's own caption line takes the legend.
  function keys() {
    var k = document.querySelectorAll(".smkey");
    for (var i = 0; i < k.length; i++) { clear(k[i]); k[i].appendChild(legend()); }
  }

  window.SlothRf = { init: function (h) { H = h; keys(); }, cell: cell, block: block, bullet: bullet,
                     count: count, colMax: colMax, newMark: newMark, pts: pts,
                     meter: meter, legend: legend };
})();
