// slothweb: the Flows view's first mode, the source by destination
// matrix (docs/web-visual-spec.md F11, §6.6; owner ruling 4 of
// 2026-10-26: matrix first, the chord second; #171 slice V4), from
// /api/flows/graph?form=matrix. The cells are glyph.js's (glyph.mx);
// this module lays the axes out and writes the addresses on them.
// window.SlothFlowMx, the hooks app.js calls:
//   SlothFlowMx.init(h)         once, main()'s helpers lent
//   SlothFlowMx.draw(c, m)      the matrix on c: {cells, max, groups}
//   SlothFlowMx.hit(e)          the address a click on c names: a row's
//                               or a cell's source, a column's
//                               destination; null for none
//   SlothFlowMx.reset()         a window or scope change: R11's scale
//                               starts again
// An address is drawn with fillText, never as markup.
(function () {
  "use strict";
  var H = null;
  // A row 18 px (R2); a cell never narrower than a count and a letter,
  // never wider than G6's 48 px bar plus its margin (§5 G6).
  var CH = 18, CW_MIN = 30, CW_MAX = 56;
  var G = { geo: null, max: 0 };

  function draw(c, m) {
    var srcs = (m && m.srcs) || [], dsts = (m && m.dsts) || [];
    var box = c.parentNode, bw = box ? box.clientWidth : c.clientWidth;
    var narrow = bw < 520;
    var x0 = narrow ? 92 : 128, y0 = narrow ? 64 : 96;
    var cw = dsts.length ? Math.floor((bw - x0) / dsts.length) : CW_MAX;
    cw = Math.max(CW_MIN, Math.min(CW_MAX, cw));
    // Wider than its box: the box scrolls, the page does not.
    c.style.width = Math.max(bw, x0 + dsts.length * cw) + "px";
    c.style.height = (srcs.length ? y0 + srcs.length * CH + 2 : CH) + "px";
    G.max = glyph.mxMax(m, G.max);
    var marks = glyph.mx(m, { x0: x0, y0: y0, cw: cw, ch: CH, max: G.max });
    glyph.paint(c, marks, H.tok);
    G.geo = { x0: x0, y0: y0, cw: cw, srcs: srcs, dsts: dsts };
    if (!srcs.length) return { cells: 0, max: 0, groups: 0 };
    var dpr = window.devicePixelRatio || 1, g = c.getContext("2d");
    var font = function (b) { return (b ? "bold " : "") + Math.round(10 * dpr) + "px " + H.css("--font-mono"); };
    var maxc = narrow ? 12 : 18;
    g.textBaseline = "middle";
    srcs.forEach(function (s, i) {
      var st = H.addrStyle(String(s.id));
      g.font = font(st.bold);
      g.fillStyle = st.color;
      g.textAlign = "left";
      g.fillText(H.cutLabel(String(s.id), maxc), 2 * dpr, (y0 + i * CH + CH / 2) * dpr, (x0 - 6) * dpr);
    });
    // A column's address reads up its header, so a column stays a cell
    // wide whatever its address.
    dsts.forEach(function (d, i) {
      var st = H.addrStyle(String(d.id));
      g.save();
      g.translate((x0 + i * cw + cw / 2) * dpr, (y0 - 4) * dpr);
      g.rotate(-Math.PI / 2);
      g.font = font(st.bold);
      g.fillStyle = st.color;
      g.textAlign = "left";
      g.fillText(H.cutLabel(String(d.id), maxc), 0, 0, (y0 - 8) * dpr);
      g.restore();
    });
    return { cells: ((m && m.cells) || []).length, max: G.max,
             groups: ((m && m.groups) || []).length };
  }

  function hit(e) {
    var geo = G.geo, c = e.currentTarget;
    if (!geo || !c) return null;
    var b = c.getBoundingClientRect(), px = e.clientX - b.left, py = e.clientY - b.top;
    var row = Math.floor((py - geo.y0) / CH), col = Math.floor((px - geo.x0) / geo.cw);
    if (py >= geo.y0 && row >= 0 && row < geo.srcs.length) return String(geo.srcs[row].id);
    if (py < geo.y0 && px >= geo.x0 && col >= 0 && col < geo.dsts.length) return String(geo.dsts[col].id);
    return null;
  }

  function reset() { G.max = 0; }

  window.SlothFlowMx = { init: function (h) { H = h; }, draw: draw, hit: hit, reset: reset,
                         CH: CH };
})();
