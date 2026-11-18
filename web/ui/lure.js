// slothweb: the KARMA and key-harvest card on the WiFi view (#187,
// #172; web_lure.h, docs/wiki/jsonl-schema.md "Credential lures").
// window.SlothLure, two hooks app.js calls:
//   SlothLure.init(h)   once, main()'s helpers lent: getJSON (scoped),
//                       errText, shortStamp
//   SlothLure.show()    when the WiFi view shows: loads /api/lures into
//                       the w-lure-* containers and keeps them current
//                       while the view is visible
// Three tables: the BSSIDs sloth's [y] view lists (beacon fan-out, or
// answers to directed probes for names never beaconed), the stations
// that left M1s unanswered, and the BSSIDs whose claimed deauths were
// followed by a victim's fresh handshake. The counts the rules read,
// not a verdict: whether a row crossed its rule's threshold is the
// alert's to say, and the Alerts view has it. A KARMA row's BSSID is a
// button to its detail (karma.js) when that module is on the page.
// Every string shown is the sensor's, and an SSID or a tool name behind
// it came over the air: textContent only, no markup sink, no attribute
// written from a value.
(function () {
  "use strict";
  var H = null;
  var POLL_MS = 15000;
  var S = { gen: 0, timer: 0 };

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

  // ── the pure half: web/tests/test_lure.c pins these out of the page ──
  function stateText(j) {
    if (!j) return "not known";
    if (j.out_of_scope) return String(j.reason || "");
    if (j.reported === false)
      return "not reported: this sloth's stream (JSONL " + (j.jsonl_version || "before 1.0.0") +
             ") does not carry KARMA or key-harvest evidence; it needs 1.3.0";
    if (j.reported === null)
      return "not known: sloth has not reported its stream version on this connection yet";
    var k = (j.karma || []).length, s = (j.stations || []).length, c = (j.chains || []).length;
    var t = k + s + c === 0 ? "none: sloth's KARMA and key-harvest tables are empty"
      : plural(k, "KARMA suspect", "KARMA suspects") + ", " +
        plural(s, "station leaving M1s unanswered", "stations leaving M1s unanswered") + ", " +
        plural(c, "deauth-then-handshake chain", "deauth-then-handshake chains");
    if (num(j.stale) && j.stale > 0)
      t += "; " + plural(j.stale, "row", "rows") + " not refreshed for 11 min left out";
    if (num(j.rejected) && j.rejected > 0)
      t += "; " + plural(j.rejected, "malformed record", "malformed records") + " refused";
    return t;
  }
  function karmaCells(r) {
    return [r.bssid, r.top_ssid || "", r.ssids, r.ie_postures > 0 ? r.ie_postures : "-",
            r.forged, r.forge_stations, r.pnl_best, r.lure_chain ? "yes" : "",
            r.score, r.tool || "", stamp(r.last_seen)];
  }
  function staCells(r) {
    return [r.sta, r.asked, r.m1_bssids, r.unanswered, r.unanswered_kde, r.answered,
            stamp(r.first_seen), stamp(r.last_seen)];
  }
  function chainCells(r) {
    return [r.bssid, r.victims, r.disconnects, stamp(r.first_seen), stamp(r.last_seen)];
  }

  var KARMA_HEAD = ["bssid", "ssid", "ssids", "postures", "forged", "to stations",
                    "pnl", "lure chain", "score", "tool", "last beacon"];
  var STA_HEAD = ["station", "asked", "m1 from", "unanswered", "with pmkid kde",
                  "answered", "first", "last"];
  var CHAIN_HEAD = ["bssid", "victims", "deauths", "first", "last"];

  // first, when given, makes the first cell's node of its value (a
  // KARMA row's BSSID: the button to its detail, karma.js).
  function table(id, head, rows, cells, first) {
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
        var td = el("td", null, k === 0 && first ? null : c[k]);
        if (k === 0 && first) td.appendChild(first(c[k]));
        tr.appendChild(td);
      }
      t.appendChild(tr);
    }
  }
  function karmaFirst(v) {
    return window.SlothKarma ? SlothKarma.button(String(v)) : document.createTextNode(String(v));
  }

  function draw(j) {
    var st = $("w-lure-state");
    if (st) st.textContent = stateText(j);
    table("w-lure-karma", KARMA_HEAD, (j && j.karma) || [], karmaCells, karmaFirst);
    table("w-lure-sta", STA_HEAD, (j && j.stations) || [], staCells);
    table("w-lure-chain", CHAIN_HEAD, (j && j.chains) || [], chainCells);
  }

  function load() {
    var gen = ++S.gen;
    H.getJSON("/api/lures").then(function (j) {
      if (gen === S.gen) draw(j);
    }).catch(function (e) {
      if (gen !== S.gen) return;
      draw(null);
      var st = $("w-lure-state");
      if (st) st.textContent = H.errText(e && e.message ? e.message : "error", e && e.body);
    });
  }

  function tick() {
    S.timer = 0;
    if (!visible()) return;
    load();
    S.timer = setTimeout(tick, POLL_MS);
  }

  window.SlothLure = {
    init: function (h) { H = h; },
    show: function () {
      if (!H) return;
      if (S.timer) clearTimeout(S.timer);
      tick();
    },
    stateText: stateText, karmaCells: karmaCells, staCells: staCells, chainCells: chainCells
  };
})();
