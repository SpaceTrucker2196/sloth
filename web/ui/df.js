// slothweb: the direction-finding card on the WiFi view (web_df.h,
// docs/wiki/direction-finding.md).
// window.SlothDf, two hooks app.js calls:
//   SlothDf.init(h)   once, main()'s helpers lent: getJSON (scoped),
//                     errText, shortStamp
//   SlothDf.show()    when the WiFi view shows: loads /api/df into the
//                     w-df-* containers and keeps them current while
//                     the view is visible
//   SlothDf.of(mac)   the latest read's row for a transmitter, or null:
//                     the access points table carries an AP's own
//                     (loudest at, margin, bearing) on its row
// h may also lend isAp(mac) (a BSSID the access points table shows, so
// the transmitters table here leaves it out) and changed() (called after
// each read, so that table refreshes its rows' figures).
// Two tables: the radios (the sensor radio and each --df-iface one,
// where it sits, on the baseline or east and north, and how much louder
// than the sensor radio it reads), and the transmitters two or more of
// them hear, the ones with a lean first. What a row says is which radio
// hears the transmitter loudest and by how much, and, from radios
// placed in two dimensions with the transmitter close to them, the
// compass point the levels lean toward. That is a lean and not a fix,
// and with unlike antennas it is not even that. A data point, not a
// verdict.
// Every string shown is the sensor's: textContent only, no markup sink,
// no attribute written from a value.
(function () {
  "use strict";
  var H = null;
  var POLL_MS = 10000;
  var S = { gen: 0, timer: 0, em: new Map() };

  function $(id) { return document.getElementById(id); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); return n; }
  function visible() { var v = $("v-wifi"); return v && !v.hidden; }
  function stamp(t) { return H && num(t) && t > 0 ? H.shortStamp(t) : "-"; }
  function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }
  function fixed(v, d, unit) { return num(v) ? v.toFixed(d) + (unit || "") : "-"; }
  function signed(v, d, unit) { return num(v) ? (v > 0 ? "+" : "") + v.toFixed(d) + (unit || "") : "-"; }

  // ── the pure half: web/tests/test_webdf.c pins these out of the page ──
  function stateText(j) {
    if (!j) return "not known";
    if (j.out_of_scope) return String(j.reason || "");
    if (j.reported === false)
      return "not reported: this sloth's stream (JSONL " + (j.jsonl_version || "before 1.0.0") +
             ") does not carry direction finding; it needs 2.2.0";
    if (j.reported === null)
      return "not known: sloth has not reported its stream version on this connection yet";
    var radios = j.radios || [], em = j.emitters || [];
    if (!radios.length)
      return "off: sloth has written no radio (it runs without --df-iface, or its next heartbeat, at most 5 min away, has not come yet)";
    var up = 0, lean = 0;
    for (var i = 0; i < radios.length; i++) if (radios[i].open && radios[i].running) up++;
    for (var k = 0; k < em.length; k++) if (em[k].quality === "lean") lean++;
    var held = num(j.held) ? j.held : em.length;
    var t = up + " of " + plural(radios.length, "radio", "radios") + " listening; " +
            plural(held, "transmitter", "transmitters") + " heard by two or more";
    if (held > em.length) t += " (" + em.length + " shown)";
    t += ", " + lean + " with a lean";
    if (up < 2) t += "; fewer than two radios listening, so nothing can be compared";
    if (num(j.stale) && j.stale > 0)
      t += "; " + plural(j.stale, "row", "rows") + " not refreshed for 11 min left out";
    if (num(j.rejected) && j.rejected > 0)
      t += "; " + plural(j.rejected, "malformed record", "malformed records") + " refused";
    return t;
  }
  function radioState(r) {
    if (!r.open) return "not open";
    if (!r.running) return "stopped";
    return r.noted > 0 ? "listening" : "no frames yet";
  }
  // Metres east and north of the operator's origin, or along the baseline.
  function placeText(r) {
    if (num(r.x_m) && num(r.y_m)) {
      return Math.abs(r.x_m).toFixed(2) + " m " + (r.x_m < 0 ? "W" : "E") + ", " +
             Math.abs(r.y_m).toFixed(2) + " m " + (r.y_m < 0 ? "S" : "N");
    }
    return fixed(r.pos_m, 2, " m");
  }
  var POINTS = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"];
  // "NW 315 +/-30": the compass point, its degrees and what a 3 dB error
  // on one radio does to it. "-" when sloth withheld it, the common case.
  function bearingText(r) {
    if (!num(r.bearing_deg) || r.bearing_deg < 0 || r.bearing_deg >= 360 || r.bearing_deg % 45)
      return "-";
    var t = POINTS[r.bearing_deg / 45] + " " + r.bearing_deg + "\u00b0";
    if (num(r.bearing_err_deg)) t += " \u00b1" + r.bearing_err_deg + "\u00b0";
    return t;
  }
  function radioCells(r) {
    return [r.radio, r.iface, r.role, placeText(r), radioState(r), r.noted,
            r.role === "sensor" ? "reference" : signed(r.bias_db, 1, " dB"),
            num(r.retune_failures) ? r.retune_failures : "-"];
  }
  // The transmitter in its channel's colour (SlothChan.mark(): an AP's
  // own, a station's last heard, else the channel this read heard it on).
  function emCells(r) {
    return [SlothChan.mark(el("span", null, String(r.mac)), "mac", String(r.mac), r.channel > 0 ? r.channel : null),
            r.channel > 0 ? SlothChan.chip(r.channel) : "-", r.quality,
            r.best_iface || (r.best_radio >= 0 ? "radio " + r.best_radio : "-"),
            fixed(r.margin_db, 1, " dB"), bearingText(r), fixed(r.along_m, 2, " m"), r.heard_by,
            stamp(r.last_seen)];
  }

  // An AP row's three figures, from its transmitter row (null: "-").
  function apCells(r) {
    if (!r) return ["-", "-", "-"];
    return [r.best_iface || (r.best_radio >= 0 ? "radio " + r.best_radio : "-"),
            fixed(r.margin_db, 1, " dB") + (r.quality === "weak" ? " weak" : ""), bearingText(r)];
  }
  function key(mac) { return String(mac).toLowerCase(); }

  var RADIO_HEAD = ["radio", "interface", "role", "position", "state", "frames noted",
                    "reads vs sensor", "retunes refused"];
  var EM_HEAD = ["transmitter", "ch", "quality", "loudest at", "margin", "bearing", "along baseline",
                 "heard by", "last heard"];

  function table(id, head, rows, cells) {
    var t = clear($(id));
    if (!t) return;
    t.hidden = !rows.length;
    if (!rows.length) return;
    var tr = el("tr");
    for (var i = 0; i < head.length; i++) tr.appendChild(el("th", null, head[i]));
    t.appendChild(tr);
    for (var r = 0; r < rows.length; r++) {
      var c = cells(rows[r]);
      tr = el("tr");
      for (var k = 0; k < c.length; k++) {
        // a cell is text, or a node (the channel's chip, a MAC in its
        // channel's colour: SlothChan)
        var td = tr.appendChild(el("td", null, c[k] instanceof Node ? null : c[k]));
        if (c[k] instanceof Node) td.appendChild(c[k]);
      }
      t.appendChild(tr);
    }
  }

  function draw(j) {
    var st = $("w-df-state");
    if (st) st.textContent = stateText(j);
    S.em = new Map();
    var em = (j && j.emitters) || [];
    for (var i = 0; i < em.length; i++) S.em.set(key(em[i].mac), em[i]);
    table("w-df-radios", RADIO_HEAD, (j && j.radios) || [], radioCells);
    // An AP the access points table shows has its figures on its own
    // row there; this table keeps the other transmitters (stations, and
    // APs outside that table's window).
    table("w-df-em", EM_HEAD, em.filter(function (r) {
      return !(H && H.isAp && H.isAp(key(r.mac)));
    }), emCells);
    if (H && H.changed) H.changed();
  }

  function load() {
    var gen = ++S.gen;
    H.getJSON("/api/df").then(function (j) {
      if (gen === S.gen) draw(j);
    }).catch(function (e) {
      if (gen !== S.gen) return;
      draw(null);
      var st = $("w-df-state");
      if (st) st.textContent = H.errText(e && e.message ? e.message : "error", e && e.body);
    });
  }

  function tick() {
    S.timer = 0;
    if (!visible()) return;
    load();
    S.timer = setTimeout(tick, POLL_MS);
  }

  window.SlothDf = {
    init: function (h) { H = h; },
    show: function () {
      if (!H) return;
      if (S.timer) clearTimeout(S.timer);
      tick();
    },
    of: function (mac) { return S.em.get(key(mac)) || null; },
    stateText: stateText, radioState: radioState, radioCells: radioCells, emCells: emCells,
    apCells: apCells, placeText: placeText, bearingText: bearingText
  };
})();
