// slothweb: the WiFi view's radar scope (owner 2026-11-19: "add a radar
// view to the wifi page like we have for ads-b and aprs"). The scope is
// ppi.js (window.SlothPPI), the one the ADS-B and APRS positions panels
// draw; the targets are /api/radar's Wi-Fi devices, the 50 most recently
// heard with sloth's distance estimate.
// window.SlothWRadar, two hooks app.js calls:
//   SlothWRadar.init(h)   once, main()'s helpers lent: getJSON (scoped),
//                         errText, openDrawer
//   SlothWRadar.show()    when the WiFi view shows: reads /api/radar every
//                         10 s while the view is visible
// A single passive sensor has a distance for a device and no bearing.
// Where direction finding gives one (df.js: three or more radios placed
// east and north, all hearing it), the device sits at that bearing and
// is drawn solid; every other device sits at its distance at an
// arbitrary angle from its address and is drawn hollow, so the ring it
// is on is the reading and its angle is not. The scope is centred on the
// sensor with north up whether or not a position is known: only the
// distances and the bearings place a mark, and the sensor's coordinates
// are never used or drawn. Colour is the device's channel's (chan.js,
// the palette every Wi-Fi list on the page uses), grey when sloth has
// named no channel for it. Every string is drawn with fillText.
(function () {
  "use strict";
  var H = null;
  var POLL_MS = 10000;
  var RANGES_M = [5, 10, 20, 50, 100, 200, 500, 1000];
  var AUTO_SHARE = 0.8, RANGE_DFLT_M = 50;
  var M_PER_DEG = 111320;
  var UNIT = { name: "m", km: 0.001 };
  var ORIGIN = { lat: 0, lon: 0 };
  var TREND_GLYPH = { approaching: "\u2198", steady: "\u2192", leaving: "\u2197" };
  var S = { gen: 0, timer: 0, ppi: null, j: null, picked: null };

  function $(id) { return document.getElementById(id); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function visible() { var v = $("v-wifi"); return v && !v.hidden; }
  function note(t) { var n = $("w-radar-note"); if (n) n.textContent = t; }

  // \u2500\u2500 the pure half: web/tests/test_wradar.c pins these out of the page \u2500\u2500
  // FNV-1a (32 bit) of the lower-case address: the arbitrary angle of a
  // device with no bearing, steady between reads (radar.js's rule).
  function addrAngle(mac) {
    var ad = String(mac).toLowerCase(), h = 2166136261;
    for (var i = 0; i < ad.length; i++) { h ^= ad.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
    return (h >>> 8) % 360;
  }
  // Direction finding's bearing for the address, or null (df.js gives
  // one only on a 45 degree point, and most rows have none).
  function dfBearing(mac) {
    var r = window.SlothDf && SlothDf.of ? SlothDf.of(mac) : null;
    return r && num(r.bearing_deg) && r.bearing_deg >= 0 && r.bearing_deg < 360 ? r.bearing_deg : null;
  }
  // A point at az degrees true and m metres from the scope's origin, as
  // the latitude and longitude ppi.js places targets by (at the equator,
  // where a degree is the same length both ways).
  function at(az, m) {
    var a = az * Math.PI / 180;
    return { lat: ORIGIN.lat + m * Math.cos(a) / M_PER_DEG, lon: ORIGIN.lon + m * Math.sin(a) / M_PER_DEG };
  }
  function label(dv) {
    var id = dv.ssid ? (dv.ssid.length > 12 ? dv.ssid.slice(0, 11) + "\u2026" : dv.ssid) : String(dv.mac).slice(-8);
    return (dv.kind === "ap" ? "\u25c6 " : "\u25a0 ") + id;
  }
  function metres(m) { return m < 10 ? m.toFixed(1) : String(Math.round(m)); }
  // Which targets keep their data block: the picked one, then the
  // farthest first, each only when no kept block sits within an eighth
  // of the range of it (in metres on the scope), so a cluster near the
  // centre is marks and one name and not a pile of overprinted text.
  // The others keep their mark and their click.
  function declutter(tg, rangeM) {
    var near = rangeM / 8, kept = [];
    var order = tg.slice().sort(function (a, b) { return (b.picked ? 1 : 0) - (a.picked ? 1 : 0) || b.m - a.m; });
    order.forEach(function (o) {
      var x = o.m * Math.sin(o.az * Math.PI / 180), y = o.m * Math.cos(o.az * Math.PI / 180);
      var clash = kept.some(function (k) { return (k.x - x) * (k.x - x) + (k.y - y) * (k.y - y) < near * near; });
      if (clash && !o.picked) { o.lines = []; return; }
      kept.push({ x: x, y: y });
    });
    return tg;
  }
  // The targets: each device with a distance, at its bearing (solid) or
  // at its arbitrary angle (hollow).
  function targets(devs, picked) {
    var out = [];
    (devs || []).forEach(function (dv) {
      if (!num(dv.m) || dv.m < 0) return;
      var br = dfBearing(dv.mac), az = br === null ? addrAngle(dv.mac) : br, p = at(az, dv.m);
      var ch = window.SlothChan ? SlothChan.of("mac", String(dv.mac)) : null;
      var col = ch !== null && window.SlothChan ? SlothChan.rgb(ch) : null;
      var gl = Object.prototype.hasOwnProperty.call(TREND_GLYPH, dv.trend) ? " " + TREND_GLYPH[dv.trend] : "";
      out.push({ id: String(dv.mac), lat: p.lat, lon: p.lon, color: col || "#8a82a0", fill: br !== null,
                 shape: "circle", lines: [label(dv), "~" + metres(dv.m) + " m" + gl + (br === null ? "" : " " + br + "\u00b0")],
                 picked: picked === dv.mac, alpha: br === null ? 0.8 : 1, m: dv.m, az: az });
    });
    return out;
  }
  function range(devs) {
    var sel = $("w-radar-range"), v = sel ? Number(sel.value) : 0;
    if (v > 0) return v;
    return SlothPPI.autoRange((devs || []).map(function (d) { return d.m; }), RANGES_M, AUTO_SHARE, RANGE_DFLT_M);
  }

  function frame(t) {
    var devs = S.j && S.j.devs ? S.j.devs.wifi : null;
    var rg = range(devs), tg = declutter(targets(devs, S.picked), rg);
    var nb = tg.filter(function (o) { return o.fill; }).length;
    var r = S.ppi.scope({ centre: ORIGIN, range: rg, unit: UNIT, targets: tg,
                          empty: devs === null ? "no Wi-Fi table attached" : "no Wi-Fi device with a distance" }, t);
    if (r) note(tg.length + " device" + (tg.length === 1 ? "" : "s") + " with a distance, " + nb +
                " with a direction-finding bearing; range " + r.range + " m, rings " + SlothPPI.fmt(r.range / 5) + " m" +
                (r.beyond ? ", " + r.beyond + " beyond range on the rim" : ""));
    return true;
  }
  function plot() {
    if (!S.ppi) {
      var c = $("w-radar");
      if (!c || !window.SlothPPI) return;
      S.ppi = SlothPPI.make(c, visible);
      S.ppi.onPick = function (mac) {
        S.picked = mac;
        S.ppi.draw(frame);
        if (H && H.openDrawer) H.openDrawer(mac);
      };
    }
    S.ppi.draw(frame);
  }
  function load() {
    var gen = ++S.gen;
    H.getJSON("/api/radar").then(function (j) {
      if (gen !== S.gen) return;
      if (j && j.out_of_scope) { S.j = null; note(String(j.reason || "")); return; }
      S.j = j;
      plot();
    }).catch(function (e) {
      if (gen !== S.gen) return;
      note(H.errText(e && e.message ? e.message : "error", e && e.body));
    });
  }
  function tick() {
    S.timer = 0;
    if (!visible()) return;
    load();
    S.timer = setTimeout(tick, POLL_MS);
  }
  var sel = $("w-radar-range");
  if (sel) sel.addEventListener("change", function () { if (S.ppi) S.ppi.draw(frame); });

  window.SlothWRadar = {
    init: function (h) { H = h; },
    show: function () {
      if (!H) return;
      if (S.timer) clearTimeout(S.timer);
      tick();
    },
    addrAngle: addrAngle, at: at, targets: targets, declutter: declutter, dfBearing: dfBearing
  };
})();
