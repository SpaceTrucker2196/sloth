// slothweb: G1 on every network fact (docs/web-visual-spec.md F1, §6.1,
// §6.9; #171 slice V1). The Overview's tiles and the status strip's
// pills each draw the 24 h series behind their number, over its
// hour-of-week band, with G1's words under the tile's glyph: the band
// for this hour and the direction since the last bucket. The footer
// carries sensor.drops the same way, because a sensor that is dropping
// frames is the fact that invalidates every other panel (§6.9, P12).
// window.SlothFacts, three hooks app.js calls:
//   SlothFacts.init(h)    once, main()'s helpers lent
//   SlothFacts.refresh()  read every fact's series again and paint;
//                         app.js calls it on the Overview's minute, on a
//                         scope change, and this module on its own
//                         minute on every other view (the strip and the
//                         footer are every view's)
//   SlothFacts.paint()    paint again from what was read, for a canvas
//                         that was hidden (zero wide) when it was read
//   SlothFacts.words(pts, band, f)  G1's words, for app.js's own tiles
// refresh() also draws the Records panel's per-type G1s (#195, §6.1).
// Same-origin relative paths only, through the page's scoped getJSON.
(function () {
  "use strict";
  var H = null;
  var REFRESH_MS = 60000;
  // Each fact: the series (web_rollup.c), the canvases it draws on, and
  // the scopes that hold it. The five V1 series are Hybrid's (tag 0,
  // web_scope.c: they count every source's records, so no single scope
  // owns them); ble.devices is Monitor's. Under a scope that does not
  // hold a series the glyph is R5's dash and the words say why, never a
  // line at zero. perSec: a counter whose bucket sum is shown per
  // second, as the tile's number is. perBucket: a counter shown as its
  // bucket sum, so its unit names the bucket (10 s or a minute, by the
  // tier). num: the footer's own number, the last bucket's value (R7),
  // where no /api/live figure stands beside the glyph.
  var FACTS = [
    { id: "alerts", metric: "live.alerts_open", strip: "s-alerts-g", tile: "k-alerts-spark",
      words: "k-alerts-w", scopes: ["hybrid"] },
    { id: "anoms", metric: "live.anomalies_open", strip: "s-anoms-g", tile: "k-anoms-spark",
      words: "k-anoms-w", scopes: ["hybrid"] },
    { id: "drops", metric: "sensor.drops", foot: "f-drops-g", num: "f-drops", tile: "k-sensor-spark",
      words: "k-sensor-w", scopes: ["hybrid"], unit: "drops", perBucket: true },
    { id: "devs", metric: "live.devices", strip: "s-devs-g", tile: "k-devs-spark",
      words: "k-devs-w", scopes: ["hybrid"] },
    { id: "rate", metric: "records.total", strip: "s-rate-g", tile: "k-rate-spark",
      words: "k-rate-w", scopes: ["hybrid"], perSec: true, unit: "rec/s" },
    { id: "ble", metric: "ble.devices", strip: "s-ble-g", tile: "k-ble-spark",
      words: "k-ble-w", scopes: ["hybrid", "monitor"] }
  ];
  var S = { gen: 0, timer: 0, got: {}, scale: {}, scaleOf: "" };

  function num(v) { return typeof v === "number" && isFinite(v); }
  function $(id) { return document.getElementById(id); }

  // G1's words (§5): the band for the last bucket's hour, lo to hi, and
  // the arrow since the bucket before; "warming" where the hour has no
  // band yet (R5's word), "no data" where there is nothing.
  function words(pts, band, f) {
    if (!pts || !pts.length) return "no data";
    var k = pts.length - 1, b = band && band[k], ar = glyph.trend(pts);
    var u = f && f.unit ? " " + f.unit : "";
    var w = b ? "band " + H.fmt(Math.max(0, b[0])) + " to " + H.fmt(b[1]) + u : "warming";
    return ar ? w + " " + ar : w;
  }

  // A counter's bucket sum per second, so the band and the line are in
  // the tile's own unit; a band is scaled with it.
  function perSec(pts, bd, step) {
    var s = step > 0 ? step : 10;
    var p = pts.map(function (x) { return [x[0], x[1] / s]; });
    var b = bd ? bd.map(function (x) { return x ? [x[0] / s, x[1] / s, x[2] / s, x[3] / s] : null; }) : null;
    return { pts: p, band: b };
  }

  function held(f) { return f.scopes.indexOf(H.scope()) >= 0; }

  // The words' unit: a per-bucket counter names its bucket, because a
  // "3 drops" band means one thing per 10 s and another per minute.
  function unitOf(f, g) {
    if (!f.unit) return "";
    return f.perBucket && g && g.step > 0 ? f.unit + " per " + glyph.dur(g.step) : f.unit;
  }

  function paintOne(f) {
    var g = S.got[f.id];
    [f.strip, f.tile, f.foot].forEach(function (id) {
      var c = id && $(id);
      if (!c || !c.clientWidth) return;
      if (!g || !g.pts.length) {
        glyph.paint(c, glyph.g1([], null, { w: c.clientWidth, h: c.clientHeight }), H.tok);
        return;
      }
      glyph.paint(c, glyph.g1(g.pts, g.band, { w: c.clientWidth, h: c.clientHeight,
        from: g.from, to: g.to, step: g.step, sens: H.sens(), scale: S.scale[f.id] }), H.tok);
    });
    if (f.words && $(f.words))
      H.set(f.words, !held(f) ? "a " + f.scopes.map(function (s) { return H.scopeWord(s); }).join(" or ") +
                                " series: none under " + H.scopeWord(H.scope())
                    : g && g.err ? "series unavailable"
                    : words(g && g.pts, g && g.band, { unit: unitOf(f, g) }));
    if (f.num && $(f.num))
      H.set(f.num, g && g.pts.length ? H.fmt(g.pts[g.pts.length - 1][1]) : "-");
  }
  function paint() { FACTS.forEach(paintOne); typesPaint(); }

  function refresh() {
    if (!H) return;
    var gen = ++S.gen;
    var now = Math.floor(Date.now() / 1000);
    var tier = H.storeOn() ? "minute" : "fine";
    var step = tier === "minute" ? 60 : 10;
    var to = now - now % step + step, from = to - 86400;
    // R11 keeps a scale across refreshes, not across scopes: another
    // scope's series is other data, and a Hybrid top would flatten it.
    if (S.scaleOf !== H.scope()) { S.scale = {}; S.scaleOf = H.scope(); }
    typesRefresh();
    FACTS.forEach(function (f) {
      if (!held(f)) { S.got[f.id] = null; S.scale[f.id] = null; paintOne(f); return; }
      Promise.all([H.series(f.metric, "", tier, from, to), H.baseline(f.metric, "")]).then(function (r) {
        if (gen !== S.gen) return;
        var s = r[0], bd = H.bands(s.points, r[1], s.kind, s.step), pts = s.points;
        if (f.perSec) { var ps = perSec(pts, bd, s.step); pts = ps.pts; bd = ps.band; }
        // R4: the tile draws the window the data covers when that is
        // under a tenth of the day, as the throughput tile does.
        var gw = glyph.win(pts, from, to);
        // R11: grown to hold the data and never shrunk on a refresh.
        S.scale[f.id] = glyph.scale(pts, bd, S.scale[f.id] || null);
        S.got[f.id] = { pts: pts, band: bd, from: gw.from, to: gw.to, step: s.step };
        paintOne(f);
      }).catch(function () {
        if (gen !== S.gen) return;
        S.got[f.id] = { pts: [], band: null, err: true };
        paintOne(f);
      });
    });
  }

  // §6.1's Records header (#195): records.rate by type, a 40 px G1 each
  // for the TYPES_SHOWN busiest types of the last hour, so a burst in
  // one type (a deauth flood) shows before it scrolls out of the
  // ticker. The keys come most recently seen first (/api/keys); the
  // first TYPES_READ are read, ranked by their hour's sum, largest
  // first. Each glyph keeps its own scale (R11) and its number is the
  // last bucket's rate (R7); the caption says the rest (R9). A type's
  // name is the server's checked key, and is only ever textContent.
  var TYPES_READ = 8, TYPES_SHOWN = 4;
  var T = { gen: 0, got: [], scale: {}, scaleOf: "", total: 0, err: false };

  function typesPaint() {
    var box = $("ticker-types"), cap = $("ticker-types-note");
    if (!box) return;
    while (box.firstChild) box.removeChild(box.firstChild);
    T.got.slice(0, TYPES_SHOWN).forEach(function (g) {
      var sp = document.createElement("span");
      sp.className = "rct";
      var k = document.createElement("span");
      k.className = "rct-k";
      k.textContent = g.key;
      var c = document.createElement("canvas");
      c.className = "sg";
      c.ariaLabel = g.key + " records per second, 1 h";
      var v = document.createElement("b");
      v.textContent = g.pts.length ? H.fmt(g.pts[g.pts.length - 1][1]) : "-";
      sp.appendChild(k); sp.appendChild(c); sp.appendChild(v);
      box.appendChild(sp);
      if (c.clientWidth)
        glyph.paint(c, glyph.g1(g.pts, g.band, { w: c.clientWidth, h: c.clientHeight,
          from: g.from, to: g.to, step: g.step, sens: H.sens(), scale: T.scale[g.key] }), H.tok);
    });
    if (cap)
      cap.textContent = T.err ? "records.rate by type: unavailable"
        : !T.total ? "records.rate by type: no types yet"
        : glyph.caption({ source: "records.rate by type", window: "1 h", tier: "fine",
                          scale: "own, rec/s", n: Math.min(TYPES_SHOWN, T.got.length) + " of " +
                          T.total + " types, busiest first" });
  }

  function typesRefresh() {
    if (!$("ticker-types")) return;
    var gen = ++T.gen;
    var now = Math.floor(Date.now() / 1000), step = 10;
    var to = now - now % step + step, from = to - 3600;
    if (T.scaleOf !== H.scope()) { T.scale = {}; T.scaleOf = H.scope(); }
    H.getJSON("/api/keys?metric=records.rate").then(function (j) {
      var ks = (j.keys || []).filter(function (k) { return typeof k.key === "string"; })
                             .slice(0, TYPES_READ);
      T.total = num(j.total) ? j.total : ks.length;
      return Promise.all(ks.map(function (k) {
        return Promise.all([H.series("records.rate", k.key, "fine", from, to),
                            H.baseline("records.rate", k.key)]).then(function (r) {
          var s = r[0], ps = perSec(s.points, H.bands(s.points, r[1], s.kind, s.step), s.step);
          var sum = 0;
          ps.pts.forEach(function (p) { if (num(p[1])) sum += p[1]; });
          var gw = glyph.win(ps.pts, from, to);
          return { key: k.key, pts: ps.pts, band: ps.band, from: gw.from, to: gw.to,
                   step: s.step, sum: sum };
        }).catch(function () { return null; });
      }));
    }).then(function (rows) {
      if (gen !== T.gen) return;
      T.err = false;
      T.got = (rows || []).filter(function (g) { return g && g.sum > 0; })
        .sort(function (a, b) { return b.sum - a.sum || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0); });
      T.got.forEach(function (g) { T.scale[g.key] = glyph.scale(g.pts, g.band, T.scale[g.key] || null); });
      typesPaint();
    }).catch(function () {
      if (gen !== T.gen) return;
      T.err = true; T.got = [];
      typesPaint();
    });
  }

  function init(h) {
    H = h;
    // The strip and the footer are on every view; the Overview's own
    // minute (app.js) refreshes them with its tiles, this one elsewhere.
    if (!S.timer) S.timer = setInterval(function () { if (!H.onOverview()) refresh(); }, REFRESH_MS);
  }

  window.SlothFacts = { init: init, refresh: refresh, paint: paint, words: words };
})();
