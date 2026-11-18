// slothweb: the WiFi channel palette (owner 2026-11-18: "a consistent
// color palette for wifi channels both 2.4 and 5ghz that's used
// throughout the app when device or ssid is shown. use cool colors for
// 2.4 ghz and warm colors for 5ghz"). The colours are palette.css's
// --ch-N and --ch6-S, written and checked in web/tools/palette.c (CHAN[]:
// 3:1 on every ground, a stripe's included, both themes; neighbours in a
// sorted list and 1, 6 and 11 held apart); this module is the one place
// a channel becomes one of them. window.SlothChan:
//   SlothChan.token(ch, band)  "--ch-36", "--ch6-2", or null for a channel
//                              in no table
//   SlothChan.color(ch, band)  that token as var(), or var(--muted): for
//                              a style
//   SlothChan.rgb(ch, band)    the colour itself, the theme's, for a canvas
//   SlothChan.band(ch, band)   "2.4", "5", "6" or "" (unknown)
//   SlothChan.chip(ch, band, text)  a span: ch as given ("6g37" stays
//                              6g37), or text, on its colour in --ch-ink;
//                              an unknown channel in muted ink, unfilled
//   SlothChan.text(ch, band)   the colour for text: that token as var(),
//                              or "" for a channel in no table (the
//                              site's own ink stays). palette.c holds
//                              every channel colour at 4.5:1 as text on
//                              --bg, --panel, --panel-2 and their
//                              greenbar stripes, both themes
//   SlothChan.paint(node, ch, band)  node's text in text(ch, band)
//   SlothChan.mark(node, kind, key, ch, band)  a Wi-Fi name's text in
//                              its channel's colour (owner 2026-11-18:
//                              "use that palette throughout the ui for
//                              all wifi devices and ssids and mac
//                              addresses depending on the current or
//                              last read channel"). kind "mac" (an AP's
//                              BSSID, a station, a client) or "ssid";
//                              key the address or the SSID's display
//                              form. The channel: ch, the record's own (the
//                              current channel) where it carries one;
//                              else what learn() holds: an AP its own, a
//                              station the one it was last heard on, an
//                              SSID its most recently heard AP's
//                              (sloth.db, /api/wifi/lastch); else none,
//                              and the node keeps its ink. Each later
//                              learn() repaints every marked node.
//   SlothChan.unmark(node)     a recycled node no longer a Wi-Fi name
//   SlothChan.learn(j)         /api/wifi/lastch's answer (an answer
//                              without its maps, as out of scope, holds
//                              nothing), and the repaint
//   SlothChan.of(kind, key)    the channel learn() holds, or null
// ch is a channel number or a channel key ("36", "6g37"). band is "2.4",
// "5" or "6" (or a row's rf.radio, "6 GHz") where the caller knows it,
// and a caller that has one passes it: a 6 GHz 5 is not 2.4 GHz's 5.
// Without it a "6g" key is 6 GHz,
// 1 to 14 2.4 and 32 to 177 5, as glyph.js smBand() and sloth's
// ap_band_label() read a bare number (a 6 GHz number alone is not told
// from the others). Text only ever reaches textContent.
(function () {
  "use strict";
  var P = (window.SLOTH_PALETTE && SLOTH_PALETTE.chan) || { "2.4": [], "5": [], "6": 0 };

  function bandOf(ch, band) {
    if (typeof band === "string") band = band.replace(/ GHz$/, "");
    if (band === "2.4" || band === "5" || band === "6") return band;
    var s = String(ch);
    if (/^6g\d+$/.test(s)) return "6";
    var n = parseInt(s, 10);
    if (!(n > 0)) return "";
    return n <= 14 ? "2.4" : n >= 32 && n <= 177 ? "5" : "";
  }
  function token(ch, band) {
    var b = bandOf(ch, band), n = parseInt(String(ch).replace(/^6g/, ""), 10);
    if (!b || !(n > 0)) return null;
    if (b === "6") return n <= 233 && P["6"] > 0 ? "--ch6-" + ((n - 1) >> 2) % P["6"] : null;
    return P[b].indexOf(n) >= 0 ? "--ch-" + n : null;
  }
  function color(ch, band) {
    var t = token(ch, band);
    return "var(" + (t || "--muted") + ")";
  }
  function rgb(ch, band) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(token(ch, band) || "--muted");
    return v && v.trim() ? v.trim() : "#8a82a0";
  }
  function chip(ch, band, text) {
    var t = token(ch, band), s = document.createElement("span");
    s.className = t ? "ch-chip" : "ch-chip unk";
    if (t) s.style.backgroundColor = color(ch, band);
    s.textContent = String(text === undefined ? ch : text);
    return s;
  }

  function text(ch, band) {
    var t = token(ch, band);
    return t ? color(ch, band) : "";
  }
  function paint(node, ch, band) {
    node.style.color = text(ch, band);
    return node;
  }

  // What /api/wifi/lastch said, by name: the MACs (an AP's own channel
  // first, then a station's) and the SSIDs.
  var own = Object.prototype.hasOwnProperty, L = { aps: map(null), stas: map(null), ssids: map(null) };
  function of(kind, key) {
    if (typeof key !== "string" || key === "") return null;
    if (kind === "ssid") return own.call(L.ssids, key) ? L.ssids[key] : null;
    var k = key.replace(/^~/, "").toLowerCase();
    return own.call(L.aps, k) ? L.aps[k] : own.call(L.stas, k) ? L.stas[k] : null;
  }
  function repaint(node) {
    var d = node.dataset;
    // The record's own channel first: it is the current one (the live
    // row's, beside its chip), where sloth.db's is up to a minute old
    // and carries no band. sloth.db's fills a name drawn without one.
    if (d.chOwn !== undefined && token(d.chOwn, d.chBand)) paint(node, d.chOwn, d.chBand);
    else paint(node, of(d.chKind, d.chKey));
  }
  function mark(node, kind, key, ch, band) {
    node.dataset.chKind = kind;
    node.dataset.chKey = String(key);
    // a recycled node (the device table's pool) drops the last row's
    if (ch !== undefined && ch !== null && ch !== "") node.dataset.chOwn = String(ch);
    else delete node.dataset.chOwn;
    if (typeof band === "string") node.dataset.chBand = band;
    else delete node.dataset.chBand;
    repaint(node);
    return node;
  }
  function unmark(node) {
    delete node.dataset.chKind;
    delete node.dataset.chKey;
    delete node.dataset.chOwn;
    delete node.dataset.chBand;
    node.style.color = "";
    return node;
  }
  // names off the air, as keys: no prototype for one to land on
  function map(o) {
    var m = Object.create(null);
    if (o && typeof o === "object")
      for (var k in o) if (own.call(o, k) && typeof o[k] === "number") m[k] = o[k];
    return m;
  }
  function learn(j) {
    L = { aps: map(j && j.aps), stas: map(j && j.stas), ssids: map(j && j.ssids) };
    var ns = document.querySelectorAll("[data-ch-kind]");
    for (var i = 0; i < ns.length; i++) repaint(ns[i]);
  }

  window.SlothChan = { token: token, color: color, rgb: rgb, chip: chip, band: bandOf,
                       text: text, paint: paint, mark: mark, unmark: unmark, learn: learn, of: of };
})();
