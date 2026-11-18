// slothweb: G8, the chain timeline (docs/web-visual-spec.md F14, §5 G8,
// §6.3 and §6.8; #171 slice V4), from /api/wifi/chain: one lane per
// stage of an attack on a BSSID (deauth, twin, assoc, karma), on one
// time axis, the links sloth made between them in words. The geometry
// is glyph.js's; this module sizes the canvases and asks for the data.
// window.SlothChain, the hooks app.js calls:
//   SlothChain.init(h)            once, main()'s helpers lent
//   SlothChain.path(r, bssid)     the route for a window {from, to} and,
//                                 optionally, one BSSID
//   SlothChain.list(box, j)       the WiFi view's chains panel: one G8
//                                 per BSSID of the answer with more than
//                                 one stage, into box; {chains, max,
//                                 singles} — singles the rows left to
//                                 the G7 rug (a BSSID with one stage
//                                 gets a rug, not a G8)
//   SlothChain.alert(j)           the alert page's chain, for the BSSID
//                                 /api/alert's device names, or hidden
//   SlothChain.drawer(mac)        the device drawer's, when the device
//                                 is a BSSID with more than one stage
//   SlothChain.reset()            a scope or window change: R11's
//                                 scales start again
// A BSSID is drawn with textContent or fillText, never as markup.
(function () {
  "use strict";
  var H = null;
  // §5 G8: 18 px a lane; the stage's words in a gutter at its left.
  var LANE = 18, GUTTER = 104, GUTTER_PHONE = 76, TIMES = 12;
  var MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;
  // R11: each BSSID's count scale, grown and never shrunk, keyed by the
  // scope and the cell width (another window is other data); the list
  // clears them all when its scope or window changes.
  var S = { max: {}, of: "", agen: 0, dgen: 0 };

  function num(v) { return typeof v === "number" && isFinite(v); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = String(text);
    return e;
  }
  function clear(c) { while (c.firstChild) c.removeChild(c.firstChild); }

  function path(r, bssid) {
    var p = "/api/wifi/chain?from=" + r.from + "&to=" + r.to + "&cols=96";
    if (typeof bssid === "string" && MAC_RE.test(bssid)) p += "&bssid=" + encodeURIComponent(bssid);
    return p;
  }

  function scaleKey(j) { return H.scope() + "\u0000" + (j.to - j.from); }

  // The columns a row's lanes hold anything in, grown into acc: [lo, hi]
  // (lo -1 for none).
  function extent(gl, n, acc) {
    function see(a, b) {
      a = Math.max(0, a);
      b = Math.min(n - 1, b);
      if (b < a) return;
      if (acc[0] < 0 || a < acc[0]) acc[0] = a;
      if (b > acc[1]) acc[1] = b;
    }
    gl.lanes.forEach(function (ln) {
      (ln.counts || []).forEach(function (v, i) { if (num(v) && v > 0) see(i, i); });
      (ln.bars || []).forEach(function (b) { see(b[0], b[1]); });
    });
    gl.links.forEach(function (k) { see(k.col, k.col); });
    return acc;
  }
  // R4: when what the lanes hold spans less than a tenth of the window,
  // G8 draws those columns only (glyph.win()'s rule) and the caption
  // says "6 min of 24 h". {lo, hi, from, to, text}, or null to draw the
  // whole window. Every chain of a list gets the one span, so the
  // chains still compare.
  function span(acc, j) {
    if (acc[0] < 0) return null;
    var a = j.from + acc[0] * j.col_s, b = j.from + (acc[1] + 1) * j.col_s;
    var wn = glyph.win([[a, 0], [b, 0]], j.from, j.to);
    return wn.shrunk ? { lo: acc[0], hi: acc[1], from: a, to: b, text: wn.text } : null;
  }
  function cut(gl, sp) {
    gl.lanes.forEach(function (ln) {
      if (ln.counts) ln.counts = ln.counts.slice(sp.lo, sp.hi + 1);
      ln.bars = (ln.bars || []).map(function (b) { return [b[0] - sp.lo, b[1] - sp.lo, b[2], b[3]]; });
    });
    gl.links.forEach(function (k) { k.col -= sp.lo; });
  }

  // One G8 on c, the row's lanes and links over the window or R4's span
  // sp, three time labels under them (R4: its start, middle and end).
  // {stages, max}.
  function paint(c, row, j, sp) {
    var gl = glyph.g8Lanes(row, j);
    var cols = j.cols, from = j.from, to = j.to;
    if (sp) { cut(gl, sp); cols = sp.hi - sp.lo + 1; from = sp.from; to = sp.to; }
    var narrow = (c.parentNode ? c.parentNode.clientWidth : c.clientWidth) < 520;
    var gx = narrow ? GUTTER_PHONE : GUTTER;
    var hh = glyph.g8Height(gl.lanes.length, gl.links, LANE) + TIMES;
    c.style.height = hh + "px";
    var w = c.clientWidth;
    // A cell's width is part of the scale: the alert page's half hour
    // and the panel's day are other cells, and must not grow each
    // other's (R11 holds one glyph to itself, not to another window).
    var key = H.scope() + "\u0000" + j.col_s + "\u0000" + String(row.bssid);
    var max = glyph.g8Max(gl.lanes, S.max[key] || 0);
    S.max[key] = max;
    var marks = glyph.g8(gl.lanes, gl.links, gl.labels,
                         { w: w, lane: LANE, gutter: gx, ncol: cols, max: max });
    var ty = hh - TIMES / 2, gw = Math.max(1, w - gx);
    [[from, gx], [Math.round((from + to) / 2), gx + gw / 2 - 18], [to, w - 38]]
      .forEach(function (t) {
        marks.push(["time", Math.max(gx, t[1]), ty, 40, 10, "--faint", H.shortStamp(t[0])]);
      });
    glyph.paint(c, marks, H.tok);
    return { stages: gl.stages, max: max };
  }

  // A BSSID's heading: the address in its hash colour, as every MAC is.
  function head(bssid) {
    var d = el("div", "chhead");
    var b = el("span", "", bssid);
    b.style.color = H.keyColor(bssid);
    d.appendChild(b);
    return d;
  }

  function list(box, j) {
    if (S.of !== scaleKey(j)) { S.max = {}; S.of = scaleKey(j); }
    clear(box);
    // Laid out before it is painted: a canvas in a hidden box is 0 wide.
    box.hidden = false;
    var rows = (j && j.bssids) || [], singles = [], chains = [], max = 0, acc = [-1, -1];
    rows.forEach(function (r) {
      var gl = glyph.g8Lanes(r, j);
      if (gl.stages < 2) { singles.push(r); return; }
      chains.push(r);
      extent(gl, j.cols, acc);
    });
    var sp = span(acc, j);
    chains.forEach(function (r) {
      box.appendChild(head(String(r.bssid)));
      var c = el("canvas", "chain");
      c.ariaLabel = "the attack chain on " + r.bssid +
                    ": deauth, twin, association and karma lanes on one time axis";
      box.appendChild(c);
      var p = paint(c, r, j, sp);
      if (p.max > max) max = p.max;
    });
    box.hidden = !chains.length;
    return { chains: chains.length, max: max, singles: singles, win: sp ? sp.text : "" };
  }
  // One row's span, for a G8 drawn alone.
  function spanOf(row, j) { return span(extent(glyph.g8Lanes(row, j), j.cols, [-1, -1]), j); }

  function caption(j, row, st) {
    var since = num(j.links_since) ? "the stream's twin_episode since " + H.shortStamp(j.links_since)
              : j.links_from === "stream" ? "no twin_episode in the stream yet" : "no stream links";
    return glyph.caption({
      source: "wifi.chain " + (row ? row.bssid : "") + ", sloth.db " + j.db + "; links: " + since,
      window: glyph.dur(j.to - j.from), tier: j.tier,
      scale: st && st.max > 0 ? "one scale, tallest " + H.fmt(st.max) + " a cell" : "",
      n: j.cols, state: st ? st.win || "" : row ? "one stage in the window: a chain draws from two" : "no data" });
  }

  // The alert page (§6.8's drawer rule, on the page an operator reads an
  // alert from): the chain of the BSSID the alert names. A window from a
  // quarter of an hour before its first observation to five minutes after
  // its last, at least half an hour, never past now.
  function alert(j) {
    var sec = document.getElementById("ad-chain"), c = document.getElementById("ad-chain-c");
    var gen = ++S.agen;
    var b = j && j.device && j.device.bssid;
    if (!sec || !c) return;
    if (!j || H.scope() === "local" || typeof b !== "string" || !MAC_RE.test(b)) {
      sec.hidden = true;
      return;
    }
    sec.hidden = false;
    c.hidden = true;
    H.set("ad-chain-note", "loading");
    var now = Math.floor(Date.now() / 1000);
    var to = Math.min(now, (num(j.last_seen) ? j.last_seen : now) + 300);
    var from = (num(j.first_seen) ? j.first_seen : to) - 900;
    if (to - from < 1800) from = to - 1800;
    H.getJSON(path({ from: from, to: to }, b)).then(function (a) {
      if (gen !== S.agen) return;
      var row = (a.bssids || [])[0];
      if (!row) { H.set("ad-chain-note", caption(a, null, null)); return; }
      var two = glyph.g8Lanes(row, a).stages > 1;
      c.hidden = !two;
      var sp = two ? spanOf(row, a) : null, st = two ? paint(c, row, a, sp) : null;
      if (st) st.win = sp ? sp.text : "";
      H.set("ad-chain-note", caption(a, row, st));
    }).catch(function (e) {
      if (gen === S.agen) H.set("ad-chain-note", H.errText(e.message));
    });
  }

  // The drawer: G8 when the device is a BSSID with more than one stage
  // in the last 24 h; nothing at all otherwise.
  function drawer(mac) {
    var box = document.getElementById("dr-chain"), c = document.getElementById("dr-chain-c");
    var gen = ++S.dgen;
    if (!box || !c) return;
    box.hidden = true;
    if (H.scope() === "local" || typeof mac !== "string" || !MAC_RE.test(mac)) return;
    var to = Math.floor(Date.now() / 1000);
    H.getJSON(path({ from: to - 86400, to: to }, mac)).then(function (a) {
      if (gen !== S.dgen) return;
      var row = (a.bssids || [])[0];
      if (!row || glyph.g8Lanes(row, a).stages < 2) return;
      box.hidden = false;
      var sp = spanOf(row, a), st = paint(c, row, a, sp);
      st.win = sp ? sp.text : "";
      H.set("dr-chain-note", caption(a, row, st));
    }).catch(function () { /* no chain: the drawer has nothing to add */ });
  }

  function reset() { S.max = {}; S.of = ""; }

  window.SlothChain = { init: function (h) { H = h; }, path: path, list: list, alert: alert,
                        drawer: drawer, reset: reset, LANE: LANE };
})();
