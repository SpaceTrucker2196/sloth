// slothweb: one BSSID's KARMA detail (#187; web_lure.h, /api/lures/bssid).
// window.SlothKarma, the hooks app.js and lure.js call:
//   SlothKarma.init(h)        once, main()'s helpers lent: getJSON
//                             (scoped), errText, keyColor, stamp,
//                             shortStamp, kvList, alertLink
//   SlothKarma.button(bssid)  a button that opens the detail (the WiFi
//                             view's lures panel), or the BSSID as text
//                             when it is not a canonical MAC
//   SlothKarma.open(bssid)    the drawer (#kdrawer)
//   SlothKarma.drawer(mac, remote)
//                             the device drawer's line (#dr-karma): what
//                             sloth's stream holds for the BSSID and a
//                             button to the detail; "-" for a row only
//                             another sloth host heard, which carries no
//                             lure data; hidden when nothing is held
// What the drawer shows is what sloth sent, never more: the
// karma_suspect row now and each change of it this connection kept,
// the KARMA_AP and KARMA_PROBE_FORGE incidents whose key names the
// BSSID (each opens its alert page, with its triage), the #151
// hardware verdict as the newest KARMA_AP record carries it, and the
// probe-response latency a beacon record carries (JSONL 1.6.0), which
// sloth puts in no verdict. Whether a count crossed a threshold is the
// alert's to say.
// Every string shown is the sensor's, and an SSID or a tool name came
// over the air: textContent only, no markup sink, no attribute written
// from a value.
(function () {
  "use strict";
  var H = null;
  var MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;
  var SEV_WORD = ["low", "warn", "crit"];
  var S = { gen: 0, dgen: 0, sel: null, back: null };

  function $(id) { return document.getElementById(id); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); return n; }
  function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }
  function stamp(t) { return H && num(t) && t > 0 ? H.shortStamp(t) : "-"; }

  // ── the pure half: web/tests/test_lure.c pins these out of the page ──
  function stateText(j) {
    if (!j) return "not known";
    if (j.out_of_scope) return String(j.reason || "");
    if (j.state === "live") return "live: in sloth's KARMA table now";
    if (j.state === "gone") return "gone: sloth retired the row at " + stamp(j.gone_ts);
    if (j.state === "stale") return "stale: sloth has not refreshed the row for 11 min";
    if (j.reported === false)
      return "not reported: this sloth's stream (JSONL " + (j.jsonl_version || "before 1.0.0") +
             ") carries no KARMA evidence; it needs 1.3.0";
    return "none: sloth's KARMA table has not held it on this connection";
  }
  function hwText(hw) {
    if (!hw) return "-";
    if (typeof hw.verdict !== "string") return "none on its newest KARMA_AP record";
    return hw.verdict + (typeof hw.signals === "string" ? " (" + hw.signals.split("+").join(", ") + ")" : "");
  }
  function latText(p) {
    if (!p) return "-";
    var d = p.n_dir > 0
      ? "directed: median " + p.med_dir_us + " µs (p10 " + p.p10_dir_us + ", p90 " + p.p90_dir_us +
        ", least " + p.min_dir_us + ") over " + plural(p.n_dir, "pair", "pairs")
      : "directed: none paired";
    var w = p.n_wild > 0
      ? "wildcard: median " + p.med_wild_us + " µs over " + plural(p.n_wild, "pair", "pairs")
      : "wildcard: none paired";
    return d + "; " + w + "; clock " + String(p.src);
  }
  function histCells(e) {
    return [stamp(e.ts), stamp(e.ts_last), e.ssids, e.ie_postures > 0 ? e.ie_postures : "-",
            e.forged, e.forge_stations, e.pnl_best, e.lure_chain ? "yes" : "", e.score,
            e.top_ssid || "", e.tool || "", stamp(e.last_seen)];
  }
  function alertText(a) {
    return String(a.type_name) + " " + (SEV_WORD[a.sev] || "?") +
           (num(a.confidence) ? " conf " + a.confidence + "%" : "") + ", " + String(a.state) +
           ", " + stamp(a.first_seen) + " to " + stamp(a.last_seen) +
           (num(a.observations) ? ", " + plural(a.observations, "observation", "observations") : "") +
           (typeof a.reason === "string" ? ", " + a.reason : "");
  }
  // Is there anything to open the detail for?
  function held(j) {
    return !!j && !j.out_of_scope && (j.state !== "none" || (j.alerts || []).length > 0 ||
                                      !!j.hw || !!j.probe_lat);
  }
  function lineText(j) {
    var t = [];
    if (j.current) t.push("score " + j.current.score + ", " + j.current.ssids + " ssids, " +
                          j.current.forged + " forged");
    else if (j.state !== "none") t.push(j.state);
    if ((j.alerts || []).length) t.push(plural(j.alerts.length, "alert", "alerts"));
    if (j.hw && typeof j.hw.verdict === "string") t.push(j.hw.verdict);
    if (j.probe_lat && j.probe_lat.n_dir > 0) t.push("probe response median " + j.probe_lat.med_dir_us + " µs");
    return t.length ? t.join("; ") : "-";
  }

  var HIST_HEAD = ["from", "to", "ssids", "postures", "forged", "to stations", "pnl",
                   "lure chain", "score", "ssid", "tool", "last beacon"];

  function render(j) {
    $("kdr-note").textContent = stateText(j);
    var body = clear($("kdr-body"));
    var c = j.current;
    H.kvList(body, (c ? [
      ["ssids beaconed", String(c.ssids)],
      ["postures", c.ie_postures > 0 ? c.ie_postures + (c.ie_collapsed ? " (collapsed: several names, one posture)" : "") : "-"],
      ["forged", String(c.forged)], ["to stations", String(c.forge_stations)],
      ["pnl best", String(c.pnl_best)], ["lure chain", c.lure_chain ? "yes" : "no"],
      ["score", String(c.score)], ["top ssid", c.top_ssid || "-"], ["tool", c.tool || "-"],
      ["last beacon", stamp(c.last_seen)]
    ] : []).concat([
      ["hardware", hwText(j.hw)],
      ["probe response", latText(j.probe_lat)]
    ]));
    var al = clear($("kdr-alerts"));
    (j.alerts || []).forEach(function (a) {
      var li = el("li", null, alertText(a));
      H.alertLink(li, String(a.id));
      al.appendChild(li);
    });
    $("kdr-alerts-note").textContent = j.alerts_held === false
      ? "no data socket: the stream's incidents are not held"
      : !(j.alerts || []).length ? "none among the stream's open and recently closed incidents"
      : j.alerts_more ? "more than shown" : "";
    var t = clear($("kdr-hist"));
    var h = (j.history || []).slice().reverse();
    t.hidden = !h.length;
    $("kdr-hist-note").textContent = !h.length ? "none kept"
      : num(j.history_changes) && j.history_changes > h.length
        ? "the newest " + h.length + " of " + j.history_changes + " changes, newest first"
        : plural(h.length, "change", "changes") + ", newest first";
    if (!h.length) return;
    var tr = el("tr");
    HIST_HEAD.forEach(function (x) { tr.appendChild(el("th", null, x)); });
    t.appendChild(tr);
    h.forEach(function (e) {
      tr = el("tr");
      histCells(e).forEach(function (x) { tr.appendChild(el("td", null, x)); });
      t.appendChild(tr);
    });
  }

  function path(bssid) { return "/api/lures/bssid?bssid=" + encodeURIComponent(bssid); }

  function close() {
    if ($("kdrawer").hidden) return;
    $("kdrawer").hidden = true;
    S.sel = null;
    S.gen++;
    if (S.back && S.back.focus && document.body.contains(S.back)) S.back.focus();
    S.back = null;
  }

  function open(bssid) {
    if (!H || typeof bssid !== "string" || !MAC_RE.test(bssid)) return;
    var gen = ++S.gen;
    S.sel = bssid;
    if ($("kdrawer").hidden) S.back = document.activeElement;
    $("kdrawer").hidden = false;
    $("kdr-close").focus();
    $("kdr-bssid").textContent = bssid;
    $("kdr-sw").style.background = H.keyColor(bssid);
    $("kdr-note").textContent = "loading";
    clear($("kdr-body"));
    clear($("kdr-alerts"));
    clear($("kdr-hist")).hidden = true;
    $("kdr-alerts-note").textContent = "";
    $("kdr-hist-note").textContent = "";
    H.getJSON(path(bssid)).then(function (j) {
      if (gen !== S.gen) return;
      if (j.out_of_scope) { $("kdr-note").textContent = "nothing under this scope: " + String(j.reason); return; }
      render(j);
    }).catch(function (e) {
      if (gen === S.gen) $("kdr-note").textContent = H.errText(e && e.message ? e.message : "error", e && e.body);
    });
  }

  function button(bssid) {
    if (typeof bssid !== "string" || !MAC_RE.test(bssid)) return document.createTextNode(String(bssid));
    var b = el("button", "lk");
    b.type = "button";
    var sw = el("span", "sw");
    sw.style.background = H ? H.keyColor(bssid) : "";
    b.appendChild(sw);
    b.appendChild(el("span", "d-dim", bssid));
    b.title = "the KARMA detail of " + bssid;
    b.addEventListener("click", function () { open(bssid); });
    return b;
  }

  function drawer(mac, remote) {
    var box = $("dr-karma");
    if (!box) return;
    var gen = ++S.dgen;
    clear(box).hidden = true;
    if (!H || typeof mac !== "string" || !MAC_RE.test(mac)) return;
    // Another host's row: its export carries no lure data.
    if (remote) {
      box.appendChild(el("span", "k", "karma"));
      box.appendChild(el("span", "d-dim", " -"));
      box.hidden = false;
      return;
    }
    H.getJSON(path(mac)).then(function (j) {
      if (gen !== S.dgen || !held(j)) return;
      box.appendChild(el("span", "k", "karma "));
      box.appendChild(el("span", "d-normal", lineText(j)));
      var b = el("button", "dt-reset", "KARMA detail");
      b.type = "button";
      b.title = "the KARMA detail of " + mac;
      b.addEventListener("click", function () { open(mac); });
      box.appendChild(document.createTextNode(" "));
      box.appendChild(b);
      box.hidden = false;
    }).catch(function () {});
  }

  function init(h) {
    H = h;
    $("kdr-close").addEventListener("click", close);
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") close(); });
    // An alert opened from here takes the screen: this drawer closes
    // under it rather than cover it. A triage button in the row
    // (frrs.js) opens nothing, so the drawer stays.
    $("kdr-alerts").addEventListener("click", function (e) {
      var t = e.target, btn = false;
      while (t && t !== this && t.tagName !== "LI") { if (t.tagName === "BUTTON") btn = true; t = t.parentNode; }
      if (!btn && t && t !== this && t.classList.contains("go")) { $("kdrawer").hidden = true; S.sel = null; S.gen++; }
    });
    function rescope() {
      if (!$("kdrawer").hidden && S.sel) { var s = S.sel; setTimeout(function () { open(s); }, 0); }
    }
    $("scope").addEventListener("click", rescope);
    $("scope").addEventListener("keydown", rescope);
  }

  window.SlothKarma = {
    init: init, open: open, close: close, button: button, drawer: drawer,
    stateText: stateText, hwText: hwText, latText: latText, histCells: histCells,
    alertText: alertText, held: held, lineText: lineText
  };
})();
