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

  window.SlothChan = { token: token, color: color, rgb: rgb, chip: chip, band: bandOf };
})();
