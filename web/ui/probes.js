// slothweb: the Probes view (owner request 2026-11-11: "a separate probes
// tab that shows clients searching for ssid's. associating these with
// clients or other devices where possible keep track of ssid's and look
// for devices probing for the same ssids"; web_probes.h).
// window.SlothProbes, the hooks app.js calls:
//   SlothProbes.init(h)   once, main()'s helpers lent: el, getJSON
//                         (scoped), errText, keyColor, shortStamp,
//                         drawStrip, DataTable, ssidSpan, openDrawer,
//                         show, scope, prefGet, prefSet
//   SlothProbes.show()    when the view shows: loads its four panels
// Four panels, top to bottom: the stations heard probing, the stations
// probing for the same networks as the one picked, the networks asked
// for, and the groups. All of it is sloth.db's (probe_clients,
// pnl_clients, pnl_ssids, assocs, seqnum_correlations), so it is what
// sloth.db retains across restarts; the window is the control's and is
// in every caption. A wildcard probe names no network: it is counted in
// a station's frames and is never listed as an SSID.
// What a row is tied to is only what sloth already has a basis for: a
// devices row for the same MAC, an association seen for it, or sloth's
// sequence-number correlation with another MAC, which is a hypothesis
// about a radio that a passive sensor corroborates and never confirms.
// The similarity is the server's (its formula is in the caption). It
// says two stations probe for the same networks, never that they have
// one owner. Every DOM string is set with textContent.
(function () {
  "use strict";
  var H = null;
  var P = { gen: 0, sgen: 0, rows: [], ss: [], from: null, sel: "", total: 0, more: false, next: 0 };
  var PAGE = 50, ROWS_MAX = 500, CELLS = 144, CELL_S = 600;
  var SORTS = { "last": "last heard first", "first": "first heard first", "ssids": "most networks first",
                "frames": "most frames first", "signal": "nearest first", "mac": "by address" };
  var SS_SORTS = { "clients": "most stations first", "last": "last asked for first",
                   "first": "first asked for first", "ssid": "by name" };
  function $(id) { return document.getElementById(id); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function own(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
  function clear(id) {
    var b = $(id);
    while (b.firstChild) b.removeChild(b.firstChild);
    return b;
  }
  function days() {
    var d = Number($("pr-days").value);
    return d === 0 || d === 1 || d === 7 || d === 30 ? d : 30;
  }
  function minShared() {
    var m = Number($("pr-min").value);
    return m >= 1 && m <= 4 ? m : 2;
  }
  function winWord(d) { return d ? glyph.dur(d * 86400) : "all sloth.db retains"; }
  function sortOf(id, table, dflt) {
    var v = $(id).value;
    return own(table, v) ? v : dflt;
  }
  function who(x) { return x.random ? "randomised" : typeof x.vendor === "string" ? x.vendor : "?"; }

  // A MAC as a button: go(mac) on a click, without the row's own.
  function macBtn(mac, random, title, go) {
    var b = H.el("button", "lk");
    b.type = "button";
    var sw = H.el("span", "sw");
    sw.style.background = H.keyColor(String(mac));
    b.appendChild(sw);
    b.appendChild(H.el("span", random ? "rnd d-dim" : "d-dim", (random ? "~" : "") + mac));
    b.title = title;
    b.addEventListener("click", function (e) { e.stopPropagation(); go(String(mac)); });
    return b;
  }
  function names(box, list, more) {
    (list || []).forEach(function (s, i) {
      if (i) box.appendChild(document.createTextNode(", "));
      box.appendChild(H.ssidSpan(String(s.ssid), s.ssid_k, s.ssid_np));
    });
    if (more > 0) box.appendChild(H.el("span", "d-dim", " +" + more + " more"));
  }

  // What sloth already ties the station to, each with its basis.
  function tied(cell, d) {
    var any = false;
    if (d.device) {
      var b = H.el("button", "lk", "device");
      b.type = "button";
      b.title = "sloth.db holds a devices row for this MAC: its drawer";
      b.addEventListener("click", function (e) { e.stopPropagation(); H.openDrawer(String(d.mac)); });
      cell.appendChild(b);
      any = true;
    }
    if (d.assoc) {
      if (any) cell.appendChild(document.createTextNode("; "));
      cell.appendChild(H.el("span", "d-dim", "associated to "));
      cell.appendChild(macBtn(d.assoc.bssid, false, "an association sloth saw for this MAC: the access " +
                              "point's drawer", H.openDrawer));
      if (d.assoc.ssid !== null) {
        cell.appendChild(document.createTextNode(" "));
        cell.appendChild(H.ssidSpan(String(d.assoc.ssid), d.assoc.ssid_k, d.assoc.ssid_np));
      }
      any = true;
    }
    (d.siblings || []).forEach(function (s) {
      if (any) cell.appendChild(document.createTextNode("; "));
      cell.appendChild(H.el("span", "d-dim", "may be one radio with "));
      cell.appendChild(macBtn(s.mac, s.random, "sloth's sequence-number correlation (gap " + s.gap + ", " +
                              s.dt_ms + " ms apart, " + s.frames + " frames): the two MACs' 802.11 counters " +
                              "ran on from one another. Consistent with one radio; a hypothesis a passive " +
                              "sensor corroborates and never confirms. Click: this MAC's shared networks",
                              select));
      any = true;
    });
    if (d.siblings_total > (d.siblings || []).length)
      cell.appendChild(H.el("span", "d-dim", " +" + (d.siblings_total - d.siblings.length) + " more"));
    if (!any) cell.appendChild(H.el("span", "d-dim", "-"));
  }

  function av(k) { return function (a) { return a[k]; }; }
  var DTC = null, DTS = null;
  function tables() {
    if (DTC) return;
    DTC = H.DataTable({ id: "prclients", label: "stations heard probing", box: $("pr-cl-box"),
      head: $("pr-cl-head"), reset: $("pr-cl-tools"), redraw: clientsDraw, cols: [
        { k: "mac", label: "mac", w: 20, min: 8, type: "mac", val: av("mac") },
        { k: "who", label: "vendor", w: 12, type: "text", val: who },
        { k: "ss", label: "networks asked for", w: 24, flex: true },
        { k: "n", label: "n", w: 4, min: 3, type: "num", val: av("ssid_count") },
        { k: "fr", label: "frames", w: 7, type: "num", val: av("frames") },
        { k: "dr", label: "directed", w: 8, type: "num", val: av("directed") },
        { k: "sig", label: "dBm", w: 5, min: 3, type: "num", val: av("signal") },
        { k: "pr", label: "24 h presence", px: 146 },
        { k: "tie", label: "tied to", w: 26 },
        { k: "ls", label: "last", w: 10, type: "time", val: av("last_seen") }
      ] });
    DTS = H.DataTable({ id: "prssids", label: "networks asked for", box: $("pr-ss-box"),
      head: $("pr-ss-head"), reset: $("pr-ss-tools"), redraw: ssidsDraw, cols: [
        { k: "ss", label: "ssid", w: 24, flex: true, type: "text", val: av("ssid") },
        { k: "cl", label: "stations", w: 8, type: "num", val: av("clients") },
        { k: "rn", label: "randomised", w: 10, type: "num", val: av("random") },
        { k: "ap", label: "an AP beacons it", w: 22, type: "num", val: av("aps") },
        { k: "fs", label: "first", w: 10, type: "time", val: av("first_seen") },
        { k: "ls", label: "last", w: 10, type: "time", val: av("last_seen") }
      ] });
  }

  function clientsDraw() {
    var box = clear("pr-cl");
    DTC.sort(P.rows).forEach(function (d) {
      var row = H.el("div", "prrow dt-row go" + (d.mac === P.sel ? " hl" : ""));
      row.role = "row";
      row.tabIndex = 0;
      var mc = H.el("span", "");
      if (glyph.isNew(d.first_seen, P.from)) {
        var nw = H.el("span", "nw");
        nw.title = "new: first seen in the last 24 h";
        mc.appendChild(nw);
      }
      var sw = H.el("span", "sw");
      sw.style.background = H.keyColor(String(d.mac));
      mc.appendChild(sw);
      mc.appendChild(H.el("span", d.random ? "rnd d-dim" : "d-dim", (d.random ? "~" : "") + d.mac));
      row.appendChild(mc);
      row.appendChild(H.el("span", d.random || d.vendor === null ? "d-dim" : "d-bright", who(d)));
      var ss = H.el("span", "prss");
      if (d.ssids && d.ssids.length) names(ss, d.ssids, d.ssid_count - d.ssids.length);
      else ss.appendChild(H.el("span", "d-dim", "wildcard probes only: no network named"));
      row.appendChild(ss);
      row.appendChild(H.el("span", "n d-normal", String(d.ssid_count)));
      row.appendChild(H.el("span", "n d-dim", num(d.frames) ? String(d.frames) : "-"));
      row.appendChild(H.el("span", "n d-dim", num(d.directed) ? String(d.directed) : "-"));
      row.appendChild(H.el("span", "n d-dim", num(d.signal) ? String(d.signal) : "-"));
      var cv = document.createElement("canvas");
      row.appendChild(cv);
      var tie = H.el("span", "prtie");
      tied(tie, d);
      row.appendChild(tie);
      row.appendChild(H.el("span", "d-dim", H.shortStamp(d.last_seen)));
      row.addEventListener("click", function () { select(String(d.mac)); });
      box.appendChild(row);
      H.drawStrip(cv, d.presence, CELLS, glyph.firstCell(d.first_seen, P.from, CELL_S, CELLS));
    });
  }

  function clientsCaption(j, d, sort) {
    var n = P.rows.length;
    $("pr-cl-cap").textContent = glyph.caption({
      source: "sloth.db probe_clients, pnl_clients, pnl_ssids", window: winWord(d),
      scale: "frames: every probe request sloth counted for the station; directed: those naming a " +
             "network; sloth keeps no count of wildcard probes",
      n: n,
      state: !n ? "no station heard probing in the window"
                : n < P.total ? n + " of " + P.total + " stations, " + SORTS[sort]
                : (j && j.seq_read === false ? "the newest correlations only" : "") });
    $("pr-cl-more").hidden = !P.more || n >= ROWS_MAX;
  }

  function clientsLoad(gen, append) {
    var d = days(), sort = sortOf("pr-cl-sort", SORTS, "last");
    var off = append ? P.next : 0;
    H.getJSON("/api/probes/clients?days=" + d + "&sort=" + encodeURIComponent(sort) + "&limit=" + PAGE +
              "&offset=" + off).then(function (j) {
      if (gen !== P.gen || j.out_of_scope) return;
      P.rows = append ? P.rows.concat(j.rows || []) : (j.rows || []);
      P.from = num(j.presence_from) ? j.presence_from : null;
      P.total = num(j.total) ? j.total : P.rows.length;
      P.more = !!j.more;
      P.next = num(j.next_offset) ? j.next_offset : 0;
      clientsDraw();
      clientsCaption(j, d, sort);
    }).catch(function (e) {
      if (gen !== P.gen) return;
      P.rows = [];
      clear("pr-cl");
      $("pr-cl-more").hidden = true;
      $("pr-cl-cap").textContent = H.errText(e.message);
    });
  }

  function ssidsDraw() {
    var box = clear("pr-ss");
    DTS.sort(P.ss).forEach(function (s) {
      var row = H.el("div", "prsrow dt-row");
      var c = H.el("span", "");
      c.appendChild(H.ssidSpan(String(s.ssid), s.ssid_k, s.ssid_np));
      row.appendChild(c);
      row.appendChild(H.el("span", "n d-normal", String(s.clients)));
      row.appendChild(H.el("span", "n d-dim", String(s.random)));
      row.appendChild(H.el("span", s.aps > 0 ? "d-bright" : "d-dim",
                           s.aps > 0 ? "yes: " + s.aps + " in sloth.db" +
                                       (num(s.ap_signal) ? ", nearest " + s.ap_signal + " dBm" : "")
                                     : "none in sloth.db"));
      row.appendChild(H.el("span", "d-dim", H.shortStamp(s.first_seen)));
      row.appendChild(H.el("span", "d-dim", H.shortStamp(s.last_seen)));
      box.appendChild(row);
    });
  }

  function ssidsLoad(gen) {
    var d = days(), sort = sortOf("pr-ss-sort", SS_SORTS, "clients");
    H.getJSON("/api/probes/ssids?days=" + d + "&sort=" + encodeURIComponent(sort) + "&limit=100")
      .then(function (j) {
        if (gen !== P.gen || j.out_of_scope) return;
        P.ss = j.rows || [];
        ssidsDraw();
        var n = P.ss.length;
        $("pr-ss-cap").textContent = glyph.caption({
          source: "sloth.db pnl_ssids by name, beacon_aps for the access points", window: winWord(d),
          scale: "stations: distinct MACs asking for it, of " + j.clients + " that named a network; " +
                 "designated networks not marked: sloth's --my-ssid is in neither sloth.db nor the stream",
          n: n,
          state: !n ? "no network asked for by name in the window"
                    : n < j.total ? n + " of " + j.total + " networks, " + SS_SORTS[sort] : "" });
      }).catch(function (e) {
        if (gen !== P.gen) return;
        P.ss = [];
        clear("pr-ss");
        $("pr-ss-cap").textContent = H.errText(e.message);
      });
  }

  // The formula as the caption says it, from the answer's own figures.
  function formula(j) {
    return "sim = sum of w over the networks both ask for / sum of w over the networks either asks for, " +
           "w = ln(N / stations asking), N = " + j.n_clients + "; uncommon: asked for by 2 to " + j.u +
           " stations; at least " + j.min + " shared uncommon";
  }

  function sharedDraw(j, d) {
    var box = clear("pr-sh");
    var head = H.el("div", "prhead");
    head.appendChild(macBtn(j.mac, /^.[26ae]/.test(String(j.mac)), "the device drawer of " + j.mac, H.openDrawer));
    head.appendChild(H.el("span", "d-dim", " asks for " + (j.ssids || []).length +
                          (j.ssids_more ? " or more" : "") + " network" +
                          ((j.ssids || []).length === 1 ? "" : "s") + " by name:"));
    box.appendChild(head);
    var ol = H.el("ol", "lst slst");
    (j.ssids || []).forEach(function (s) {
      var li = H.el("li", "");
      li.appendChild(H.ssidSpan(String(s.ssid), s.ssid_k, s.ssid_np));
      li.appendChild(H.el("span", "d-dim", s.df === 1 ? "1 station asks for it" : s.df + " stations ask for it"));
      li.appendChild(H.el("span", "d-normal", "w " + s.w.toFixed(3)));
      li.appendChild(H.el("span", s.uncommon ? "d-bright" : "d-dim",
                          s.uncommon ? "uncommon" : s.df < 2 ? "only this station" : "common: no candidate by it"));
      ol.appendChild(li);
    });
    if (!(j.ssids || []).length)
      ol.appendChild(H.el("li", "sub", "no network asked for by name in the window (wildcard probes only)"));
    box.appendChild(ol);
    box.appendChild(H.el("div", "label", "stations probing for the same networks"));
    var rl = H.el("ol", "lst slst");
    (j.rows || []).forEach(function (r) {
      var li = H.el("li", "");
      li.appendChild(macBtn(r.mac, r.random, "this station's own shared networks", select));
      li.appendChild(H.el("span", r.random ? "d-dim" : "d-bright", who(r)));
      li.appendChild(H.el("span", "d-bright", "sim " + r.sim.toFixed(3)));
      var sh = H.el("span", "d-dim", r.shared_uncommon + " uncommon of " + r.shared_n + " shared: ");
      names(sh, r.shared, r.shared_n - (r.shared || []).length);
      li.appendChild(sh);
      rl.appendChild(li);
    });
    if (!(j.rows || []).length)
      rl.appendChild(H.el("li", "sub", "none: no other station asks for " + j.min + " of its uncommon networks"));
    box.appendChild(rl);
    var n = (j.rows || []).length;
    $("pr-sh-cap").textContent = glyph.caption({
      source: "sloth.db pnl_ssids; " + formula(j), window: winWord(d), n: n,
      state: (n < j.total ? n + " of " + j.total + " stations, the most similar" : "") +
             (j.capped ? (n < j.total ? "; " : "") + "candidates capped" : "") });
  }

  function select(mac) {
    P.sel = mac;
    var gen = ++P.sgen, d = days();
    if (DTC) clientsDraw();
    $("pr-sh-cap").textContent = "loading";
    H.getJSON("/api/probes/shared?mac=" + encodeURIComponent(mac) + "&days=" + d + "&min=" + minShared())
      .then(function (j) {
        if (gen !== P.sgen || j.out_of_scope) return;
        sharedDraw(j, d);
      }).catch(function (e) {
        if (gen !== P.sgen) return;
        clear("pr-sh");
        $("pr-sh-cap").textContent = H.errText(e.message);
      });
  }

  function groupsLoad(gen) {
    var d = days();
    H.getJSON("/api/probes/groups?days=" + d + "&min=" + minShared()).then(function (j) {
      if (gen !== P.gen || j.out_of_scope) return;
      var box = clear("pr-gr");
      (j.groups || []).forEach(function (g) {
        var card = H.el("div", "prgrp");
        card.appendChild(H.el("div", "d-bright", g.clients + " stations probe for " + g.ssids +
                              " of the same uncommon network" + (g.ssids === 1 ? "" : "s")));
        var ms = H.el("div", "prmacs");
        (g.macs || []).forEach(function (m) {
          ms.appendChild(macBtn(m.mac, m.random, "this station's own shared networks", select));
        });
        if (g.clients > (g.macs || []).length)
          ms.appendChild(H.el("span", "d-dim", "+" + (g.clients - g.macs.length) + " more"));
        card.appendChild(ms);
        var ns = H.el("div", "prss");
        names(ns, g.names, g.ssids - (g.names || []).length);
        card.appendChild(ns);
        box.appendChild(card);
      });
      var n = (j.groups || []).length;
      $("pr-gr-cap").textContent = glyph.caption({
        source: "sloth.db pnl_ssids; a group: stations linked, directly or through one another, by at " +
                "least " + j.min + " shared uncommon networks (asked for by 2 to " + j.u + " of " +
                j.n_clients + " stations)", window: winWord(d), n: n,
        state: (!n ? "no group in the window" : n < j.total ? n + " of " + j.total + " groups, the most shared first" : "") +
               (j.capped ? "; capped: " + j.ssids_read + " of " + j.ssids_uncommon + " uncommon networks read" : "") });
    }).catch(function (e) {
      if (gen !== P.gen) return;
      clear("pr-gr");
      $("pr-gr-cap").textContent = H.errText(e.message);
    });
  }

  function show() {
    if (!H) return;
    var gen = ++P.gen;
    // Under Local the view's empty state says why; nothing is asked.
    if (H.scope() === "local") return;
    tables();
    clientsLoad(gen, false);
    ssidsLoad(gen);
    groupsLoad(gen);
    if (P.sel) select(P.sel);
    else {
      clear("pr-sh");
      $("pr-sh-cap").textContent = "pick a station above: the stations asking for the same uncommon networks";
    }
  }

  function init(h) {
    H = h;
    // The four controls are kept in this browser (slothweb.v1.probes.*),
    // each put back only when it is one of its own options.
    ["pr-days", "pr-min", "pr-cl-sort", "pr-ss-sort"].forEach(function (id) {
      var c = $(id), v = H.prefGet("probes." + id);
      for (var i = 0; typeof v === "string" && i < c.options.length; i++)
        if (c.options[i].value === v) c.value = v;
      c.addEventListener("change", function () {
        H.prefSet("probes." + id, c.value);
        show();
      });
    });
    $("pr-cl-more").addEventListener("click", function () { clientsLoad(P.gen, true); });
    // The WiFi view's clients panel points here.
    $("w-probes-go").addEventListener("click", function () { H.show("probes"); });
  }

  window.SlothProbes = { init: init, show: show, select: select };
})();
