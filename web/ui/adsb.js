// slothweb: the ADS-B panel (#26, 2026-11-05, web_adsb.h, docs/wiki/adsb.md).
// window.SlothAdsb, one hook app.js calls when the view shows:
//   SlothAdsb.show()   loads /api/adsb into the adsb-* containers and
//                      keeps it current while the view is visible
// Same-origin relative paths only, every value shown with textContent,
// no map tiles and nothing fetched from anywhere else: the position plot
// is drawn from the rows' own coordinates on a plain canvas. The SDR is a
// passive radio, so the view is Monitor's and Hybrid's, as BLE is; under
// Local the route answers out_of_scope and app.js shows the scope note.
// The aircraft table is app.js's DataTable (window.SlothTables.make), as
// every table on the page is. A row's figures are as of its last
// adsb_aircraft record, which sloth writes only on a change of altitude
// band, position cell, squawk, emergency, callsign or category (or the
// 300 s heartbeat): the page says so rather than implying a live feed.
// The other sloth hosts (--peer; web_fleetview.h, owner request
// 2026-11-11): with All sites the table and the inventory carry the
// aircraft only a peer heard, in the grey state (--tui-dim, no altitude
// or signal colour) with the host's name beside the address, and a
// local aircraft a peer also heard gets "+name". On the plot a peer's
// aircraft is its last position only, grey, labelled with its host: a
// peer sends no track, so none is drawn as if heard here. Its detail
// names the hosts and each one's figures. Peer strings are textContent
// and fillText only.
(function () {
  "use strict";
  var POLL_MS = 5000, ALT_SPAN = 45000, RSSI_LO = -50;
  var timer = 0, gen = 0, last = null, sel = null;
  // H (app.js's helpers) is declared with the alert link below.
  function fvq() { return H && H.fvQuery ? H.fvQuery("adsb") : ""; }
  function fvMark(a) { return H && H.fvMark ? H.fvMark(a) : null; }
  function fvName(x) { return H && H.fvName ? H.fvName(x) : String(x && x.site || "?"); }
  function remote(a) { return a && a.remote === true; }

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); return n; }
  function set(id, text) { var e = $(id); if (e) e.textContent = text; }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function fx(v, dp) { return num(v) ? v.toFixed(dp) : "-"; }
  function heatClass(f) { return f < 0.15 ? "h0" : f < 0.40 ? "h1" : f < 0.70 ? "h2" : "h3"; }
  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return v && v.trim() ? v.trim() : fallback;
  }
  function heatColor(f) {
    return cssVar("--heat-" + (f < 0.15 ? 0 : f < 0.40 ? 1 : f < 0.70 ? 2 : 3), "currentColor");
  }
  function visible() { var v = $("v-adsb"); return v && !v.hidden; }
  function age(ts, now) {
    if (!num(ts) || ts <= 0) return "-";
    var a = Math.max(0, now - ts);
    return a < 60 ? a + "s" : a < 3600 ? Math.floor(a / 60) + "m" : Math.floor(a / 3600) + "h";
  }
  // The squawks the decoder reports for itself as an emergency are in
  // `emergency`; these three are the codes ICAO reserves (7500 unlawful
  // interference, 7600 radio failure, 7700 emergency), shown, not judged.
  var SPECIAL = { "7500": "unlawful interference", "7600": "radio failure", "7700": "emergency" };
  function emerg(a) { return a.state === "live" && a.emergency && a.emergency !== "none"; }
  // A peer's row has one "alt" (its newest, barometric else geometric).
  function altOf(a) {
    return num(a.alt_baro) ? a.alt_baro : num(a.alt_geom) ? a.alt_geom : num(a.alt) ? a.alt : null;
  }
  function altText(a) {
    if (a.on_ground) return "ground";
    var v = altOf(a);
    return num(v) ? String(v) : "-";
  }
  function rateOf(a) { return num(a.baro_rate) ? a.baro_rate : num(a.geom_rate) ? a.geom_rate : null; }
  function rateText(a) {
    var v = rateOf(a);
    if (!num(v)) return "-";
    return (v > 64 ? "↑" : v < -64 ? "↓" : "→") + Math.abs(v);
  }
  function label(a) { return a.flight || a.hex; }

  // The open ADSB_EMERGENCY incident on an aircraft (#186), as /api/adsb
  // names it: the row's ALERT cell and the detail's alert line open its
  // alert page through app.js's go(). sloth only flags the declaration
  // (ADS-B is unauthenticated); the page only links it. WARN (held)
  // reads ALERT in the peak colour, LOW (first sight) alert, one down.
  var H = null;
  var ALERT_ID_RE = /^s[0-9A-Za-z]{1,24}$/;
  function alertOf(a) {
    return a.alert && typeof a.alert.id === "string" && ALERT_ID_RE.test(a.alert.id) ? a.alert : null;
  }
  function alertMark(a) {
    var al = alertOf(a);
    if (!al) return null;
    var held = al.sev >= 1;
    var m = el("span", "go adsb-alert " + (held ? "h3" : "h2"), held ? "ALERT" : "alert");
    m.tabIndex = 0;
    m.role = "link";
    m.title = "ADSB_EMERGENCY " + (held ? "held" : "first sight") + ": flag only, unverified";
    function open(e) { e.stopPropagation(); if (H && H.go) H.go("alert", { id: al.id }); }
    m.addEventListener("click", open);
    m.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(e); } });
    return m;
  }

  function getJSON(path) {
    return fetch(path, { credentials: "same-origin", cache: "no-store" }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
  }

  // ── the header: the decoder's sensor_health and the table's counts ─
  function header(j) {
    var now = num(j.now) ? j.now : Math.floor(Date.now() / 1000);
    var s = j.sensor;
    var h = clear($("adsb-head"));
    if (!s && !j.total) {
      h.appendChild(el("span", "", "ADS-B: no decoder"));
      var e = $("adsb-empty");
      e.hidden = false;
      e.textContent = "no adsb records yet: sloth needs --adsb /run/readsb/aircraft.json (or another readsb / dump1090-fa aircraft.json), docs/wiki/adsb.md";
      $("adsb-head2").textContent = "";
      return;
    }
    $("adsb-empty").hidden = true;
    h.appendChild(el("span", "", "ADS-B: decoder "));
    var st = s ? s.state : "-";
    h.appendChild(el("b", st === "live" ? "h0" : st === "waiting" ? "h1" : st === "stale" ? "h2" : st === "error" ? "h3" : "d-dim", st));
    h.appendChild(el("span", "", "  aircraft "));
    h.appendChild(el("b", "", String(j.live)));
    h.appendChild(el("span", "", " live, " + j.with_pos + " with position" + (j.total > j.live ? ", " + (j.total - j.live) + " gone" : "")));
    if (j.emergency) {
      h.appendChild(el("span", "", "  "));
      h.appendChild(el("b", "h3", j.emergency + " reporting an emergency"));
    }
    h.appendChild(el("span", "d-dim", "  src " + (j.src || (s && s.src) || "-") +
      (s && num(s.age_s) ? "  decoder clock " + s.age_s + "s ago" : "") +
      (s ? "  health " + age(s.ts, now) + " ago" : "")));
    var h2 = clear($("adsb-head2"));
    if (!s) return;
    var errs = s.read_errors + s.parse_errors;
    h2.appendChild(el("span", "", "decoder messages " + s.messages + "  reads " + s.reads + "  expired " + s.expired + "  "));
    h2.appendChild(el("span", errs ? "h2" : "", "errors " + errs));
    if (s.overflow) h2.appendChild(el("span", "h2", "  overflow " + s.overflow));
    if (s.bad_entries) h2.appendChild(el("span", "h1", "  bad entries " + s.bad_entries));
    if (s.err) h2.appendChild(el("span", "h3", "  " + s.err));
    h2.appendChild(el("span", "", "  records " + j.records + (j.evictions ? "  evicted " + j.evictions : "") +
      (j.aged ? "  aged " + j.aged : "") + (j.rejected ? "  rejected " + j.rejected : "")));
  }

  // ── the table ────────────────────────────────────────────────────
  // One of app.js's DataTable (the owner's 2026-10-26 ruling: every table
  // on the page is one implementation). With no sort set the rows stay
  // in the server's order: an emergency first, live before gone, the
  // most recently heard first.
  var T = null, rows = [];
  function val(k) { return function (a) { return num(a[k]) ? a[k] : null; }; }
  var COLS = [
    { k: "hx", label: "HEX", w: 8, min: 6, type: "text", val: function (a) { return a.hex; } },
    { k: "fl", label: "FLIGHT", w: 9, min: 4, type: "text", val: function (a) { return a.flight || ""; } },
    { k: "sq", label: "SQWK", w: 5, min: 4, type: "text", val: function (a) { return a.squawk || ""; } },
    { k: "ct", label: "CAT", w: 4, min: 3, type: "text", val: function (a) { return a.category || ""; } },
    { k: "al", label: "ALT ft", w: 7, min: 4, num: true, type: "num", val: function (a) { return a.on_ground ? -1 : altOf(a); } },
    { k: "vs", label: "V/S", w: 7, min: 4, num: true, type: "num", val: rateOf },
    { k: "gs", label: "GS kt", w: 6, min: 3, num: true, type: "num", val: val("gs") },
    { k: "tk", label: "TRK", w: 5, min: 3, num: true, type: "num", val: val("track") },
    { k: "ps", label: "POSITION", w: 19, min: 6, type: "text", val: function (a) { return num(a.lat) ? a.lat + "," + a.lon : ""; } },
    { k: "rs", label: "RSSI", w: 6, min: 4, num: true, type: "num", val: val("rssi") },
    { k: "sg", label: "SIGNAL", w: 10, min: 5, type: "num", val: val("rssi") },
    { k: "ms", label: "MSGS", w: 7, min: 4, num: true, type: "num", val: val("messages") },
    { k: "sr", label: "SOURCE", w: 10, min: 4, type: "text", val: function (a) { return a.source_type || ""; } },
    { k: "st", label: "STATE", w: 5, min: 4, type: "text", val: function (a) { return a.state || ""; } },
    { k: "ag", label: "HEARD", w: 6, min: 3, type: "time", val: val("last_seen") },
    { k: "ak", label: "ALERT", w: 6, min: 5, type: "num", val: function (a) { var al = alertOf(a); return al ? al.sev + 1 : 0; } }
  ];
  function table() {
    if (T || !window.SlothTables || !$("adsb-box")) return T;
    T = window.SlothTables.make({ id: "adsb", label: "aircraft", box: $("adsb-box"),
      head: $("adsb-thead"), reset: $("adsb-tools"), redraw: drawRows, cols: COLS });
    return T;
  }
  function cell(cls, text) { var c = el("span", cls); if (text !== undefined) c.textContent = String(text); return c; }
  function rssiFrac(v) { return Math.max(0, Math.min(1, (v - RSSI_LO) / -RSSI_LO)); }
  // The signal cell (owner ruling 2026-11-11: every signal graphic is
  // the meter, glyph.sm). The decoder's RSSI is dBFS, a level against
  // its own full scale and not dBm, so no S-units and no band row: the
  // segmented face over RSSI_LO..0 in ten equal segments, lit to the
  // row's last RSSI. A row carries one reading, so there are no ticks.
  var SM_DBFS = glyph.smScale(RSSI_LO, 0, -RSSI_LO / 10, 10, 0);
  function sigCell(a) {
    var sig = cell("c-sg"), v = num(a.rssi) ? a.rssi : null;
    var words = v === null ? "RSSI: no reading"
      : "RSSI " + v.toFixed(1) + " dBFS on a " + RSSI_LO + " to 0 dBFS meter";
    sig.title = words;
    if (window.SlothRf) window.SlothRf.meter(sig, v, { scale: SM_DBFS }, words);
    return sig;
  }
  // A row under the columns: bright when it has a position, normal
  // without, dim once gone; an emergency or a reserved squawk in the
  // peak heat colour on its own cells (text colour only, no row tint).
  // An aircraft only another sloth host heard: grey throughout, the
  // host's name after the address, what this decoder alone knows "-".
  function remoteRow(a, now) {
    var r = el("div", "adsbrow dt-row remote" + (sel === a.hex ? " on" : ""));
    var hx = cell("c-hx", a.hex);
    var fm = fvMark(a);
    if (fm) hx.appendChild(fm);
    r.appendChild(hx);
    r.appendChild(cell("c-fl", a.flight || "-"));
    r.appendChild(cell("c-sq", a.squawk || "-"));
    r.appendChild(cell("c-ct", a.category || "-"));
    r.appendChild(cell("c-al n", altText(a)));
    r.appendChild(cell("c-vs n", "-"));
    r.appendChild(cell("c-gs n", fx(a.gs, 0)));
    r.appendChild(cell("c-tk n", fx(a.track, 0)));
    r.appendChild(cell("c-ps", num(a.lat) ? a.lat.toFixed(3) + ", " + a.lon.toFixed(3) : "-"));
    r.appendChild(cell("c-rs n", fx(a.rssi, 1)));
    r.appendChild(cell("c-sg", "-"));
    r.appendChild(cell("c-ms n", num(a.messages) ? a.messages : "-"));
    r.appendChild(cell("c-sr", "-"));
    r.appendChild(cell("c-st", "-"));
    r.appendChild(cell("c-ag", age(a.last_seen, now)));
    r.appendChild(cell("c-ak", "-"));
    r.tabIndex = 0;
    function pick() { sel = a.hex; remoteDetail(a, now); drawRows(); histLoad(a.hex); }
    r.addEventListener("click", pick);
    r.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
    return r;
  }
  function row(a, now) {
    if (remote(a)) return remoteRow(a, now);
    var on = sel === a.hex;
    var cls = a.state === "gone" ? "d-dim" : num(a.lat) ? "d-bright" : "d-normal";
    var r = el("div", "adsbrow dt-row " + cls + (on ? " on" : ""));
    r.appendChild(cell("c-hx", a.hex));
    if (window.SlothSubNotes) window.SlothSubNotes.mark(r.firstChild, "aircraft", a.hex);
    var plus = fvMark(a);
    if (plus) r.firstChild.appendChild(plus);
    r.appendChild(cell("c-fl" + (emerg(a) ? " h3" : ""), a.flight || "-"));
    r.appendChild(cell("c-sq" + (SPECIAL[a.squawk] || emerg(a) ? " h3" : ""), a.squawk || "-"));
    r.appendChild(cell("c-ct", a.category || "-"));
    var alt = altOf(a);
    r.appendChild(cell("c-al n " + (a.on_ground ? "d-dim" : num(alt) ? heatClass(Math.max(0, alt) / ALT_SPAN) : "d-dim"), altText(a)));
    r.appendChild(cell("c-vs n", rateText(a)));
    r.appendChild(cell("c-gs n", fx(a.gs, 0)));
    r.appendChild(cell("c-tk n", fx(a.track, 0)));
    r.appendChild(cell("c-ps", num(a.lat) ? a.lat.toFixed(3) + ", " + a.lon.toFixed(3) : "-"));
    r.appendChild(cell("c-rs n " + (num(a.rssi) ? heatClass(rssiFrac(a.rssi)) : "d-dim"), fx(a.rssi, 1)));
    r.appendChild(sigCell(a));
    r.appendChild(cell("c-ms n", num(a.messages) ? a.messages : "-"));
    r.appendChild(cell("c-sr", a.source_type || "-"));
    r.appendChild(cell("c-st", a.state));
    r.appendChild(cell("c-ag d-dim", age(a.last_seen, now)));
    var ac = cell("c-ak");
    var mk = alertMark(a);
    if (mk) ac.appendChild(mk); else { ac.textContent = "-"; ac.className = "c-ak d-dim"; }
    r.appendChild(ac);
    r.tabIndex = 0;
    function pick() { sel = a.hex; detail(a, now); drawRows(); histLoad(a.hex); }
    r.addEventListener("click", pick);
    r.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
    return r;
  }
  function drawRows() {
    if (!last) return;
    var j = last, now = num(j.now) ? j.now : Math.floor(Date.now() / 1000);
    var t = table();
    var ordered = t ? t.sort(rows, true) : rows.slice();
    var body = clear($("adsb-rows"));
    var nrem = rows.filter(remote).length;
    set("adsb-count", j.live + " live" + (j.total > j.live ? ", " + (j.total - j.live) + " gone" : "") +
      (nrem ? ", " + nrem + " heard by other sloth hosts (grey)" +
              (j.fleet && j.fleet.remote_more ? ", the first " + nrem : "") : ""));
    ordered.forEach(function (a) { body.appendChild(row(a, now)); });
  }

  // ── the detail: one aircraft's figures ───────────────────────────
  function detail(a, now) {
    var box = $("adsb-detail");
    box.hidden = false;
    set("adsb-detail-name", label(a) + (a.flight ? " (" + a.hex + ")" : ""));
    var kv = clear($("adsb-detail-kv"));
    if (window.SlothSubNotes) window.SlothSubNotes.show("adsb", "aircraft", a.hex);
    [["address", a.hex + (a.non_icao ? " (non-ICAO: TIS-B or similar)" : " (ICAO 24-bit)")],
     ["callsign", a.flight || "-"],
     ["squawk", a.squawk ? a.squawk + (SPECIAL[a.squawk] ? " (reserved: " + SPECIAL[a.squawk] + ")" : "") : "-"],
     ["emergency", a.emergency || "- (not sent)"],
     ["category", a.category || "-"],
     ["altitude", a.on_ground ? "on the ground" :
        (num(a.alt_baro) ? a.alt_baro + " ft baro" : "-") + (num(a.alt_geom) ? ", " + a.alt_geom + " ft geometric" : "")],
     ["altitude band", a.alt_band === -2 ? "ground" : a.alt_band < 0 ? "unknown" : String(a.alt_band)],
     ["vertical rate", num(rateOf(a)) ? rateOf(a) + " ft/min" + (num(a.baro_rate) ? " (baro)" : " (geometric)") : null],
     ["ground speed", num(a.gs) ? a.gs.toFixed(1) + " kt" : null],
     ["track", num(a.track) ? a.track.toFixed(1) + " deg true" : null],
     ["position", num(a.lat) ? a.lat.toFixed(5) + ", " + a.lon.toFixed(5) + (num(a.pos_ts) ? " (" + age(a.pos_ts, now) + " ago)" : "") : "-"],
     ["track points", String((a.track_pts || []).length)],
     ["RSSI", num(a.rssi) ? a.rssi.toFixed(1) + " dBFS" : null],
     ["messages", num(a.messages) ? String(a.messages) : null],
     ["decoder source", a.source_type || "-"],
     ["state", a.state],
     ["first seen", age(a.first_seen, now) + " ago"],
     ["last heard", age(a.last_seen, now) + " ago"],
     ["last record", age(a.ts, now) + " ago (" + a.records + " records)"]
    ].forEach(function (p) {
      if (p[1] === null) return;
      kv.appendChild(el("dt", "", p[0]));
      kv.appendChild(el("dd", "", p[1]));
    });
    var mk = alertMark(a);
    if (mk) {
      kv.appendChild(el("dt", "", "alert"));
      var dd = el("dd", "");
      dd.appendChild(mk);
      dd.appendChild(el("span", "d-dim", " ADSB_EMERGENCY, flag only: ADS-B is unauthenticated and sloth cannot verify it"));
      kv.appendChild(dd);
    }
  }
  // A peer's aircraft: what its newest row says, under the host that
  // heard it; each host's own figures follow from /api/adsb/aircraft.
  function remoteDetail(a, now) {
    var box = $("adsb-detail");
    box.hidden = false;
    set("adsb-detail-name", label(a) + (a.flight ? " (" + a.hex + ")" : "") + ", heard by " +
      (a.sites || []).map(fvName).join(", "));
    var kv = clear($("adsb-detail-kv"));
    // Notes are on what this site heard: none on another host's aircraft.
    if (window.SlothSubNotes) window.SlothSubNotes.show("adsb", "aircraft", null);
    [["address", a.hex + (a.non_icao ? " (non-ICAO: TIS-B or similar)" : " (ICAO 24-bit)")],
     ["heard by", (a.sites || []).map(fvName).join(", ") || fvName(a)],
     ["callsign", a.flight || "-"],
     ["squawk", a.squawk ? a.squawk + (SPECIAL[a.squawk] ? " (reserved: " + SPECIAL[a.squawk] + ")" : "") : "-"],
     ["emergency", a.emergency || "- (not sent)"],
     ["category", a.category || "-"],
     ["altitude", a.on_ground ? "on the ground" : num(a.alt) ? a.alt + " ft (that host's newest)" : "-"],
     ["ground speed", num(a.gs) ? a.gs.toFixed(1) + " kt" : null],
     ["track", num(a.track) ? a.track.toFixed(1) + " deg true" : null],
     ["position", num(a.lat) ? a.lat.toFixed(5) + ", " + a.lon.toFixed(5) + (num(a.pos_ts) ? " (" + age(a.pos_ts, now) + " ago)" : "") : "-"],
     ["RSSI", num(a.rssi) ? a.rssi.toFixed(1) + " dBFS at that host" : null],
     ["messages", num(a.messages) ? String(a.messages) : null],
     ["first seen", age(a.first_seen, now) + " ago"],
     ["last heard", age(a.last_seen, now) + " ago"]
    ].forEach(function (p) {
      if (p[1] === null) return;
      kv.appendChild(el("dt", "", p[0]));
      kv.appendChild(el("dd", "d-dim", p[1]));
    });
  }
  // What each other sloth host reported of the aircraft (the detail
  // route's "fleet"), one line a host.
  function fleetLines(kv, f) {
    if (!f || !Array.isArray(f.rows) || !f.rows.length) return;
    kv.appendChild(el("dt", "", f.remote ? "other sloth hosts" : "also heard by"));
    kv.appendChild(el("dd", "d-dim", f.remote && typeof f.note === "string" ? f.note : ""));
    f.rows.forEach(function (x) {
      var t = [x.flight ? "callsign " + x.flight : null, x.squawk ? "squawk " + x.squawk : null,
               x.on_ground ? "on the ground" : num(x.alt) ? x.alt + " ft" : null,
               num(x.lat) ? x.lat.toFixed(3) + ", " + x.lon.toFixed(3) : null,
               num(x.gs) ? x.gs.toFixed(0) + " kt" : null,
               H && H.stamp ? "first " + H.stamp(x.first_seen) : null,
               H && H.stamp ? "last " + H.stamp(x.last_seen) : null];
      kv.appendChild(el("dt", "fv-host", fvName(x)));
      kv.appendChild(el("dd", "d-dim", t.filter(function (s) { return s !== null; }).join(", ")));
    });
  }
  function closeDetail() {
    $("adsb-detail").hidden = true;
    sel = null; histHex = null; histPts = [];
    drawRows(); drawSeen(); plot(last);
  }

  // ── the plot: positions and tracks, north up, no map ─────────────
  // Equirectangular around the rows' own centre, longitude scaled by
  // cos(latitude) so distances read true near the middle; a scale bar
  // in km. Colour is altitude on the heat ramp over 45,000 ft.
  function plot(j) {
    var c = $("adsb-plot");
    if (!c || !j) return;
    var dpr = window.devicePixelRatio || 1;
    var W = Math.max(240, c.clientWidth || 480), H = 360;
    c.width = W * dpr; c.height = H * dpr;
    var g = c.getContext("2d");
    if (!g) return;
    g.scale(dpr, dpr);
    g.clearRect(0, 0, W, H);
    var pts = [];
    (j.rows || []).forEach(function (a) {
      (a.track_pts || []).forEach(function (p) { pts.push(p); });
      if (num(a.lat)) pts.push([0, a.lat, a.lon, null]);
    });
    // The selected aircraft's recorded track (sloth.db), as [ts, lat, lon, alt].
    var rec = histHex && histHex === sel ? histPts.filter(function (p) { return num(p[3]) && num(p[4]); })
      .map(function (p) { return [p[0], p[3], p[4], p[2]]; }) : [];
    rec.forEach(function (p) { pts.push(p); });
    var dim = cssVar("--tui-dim", "#888");
    g.font = "11px monospace";
    if (!pts.length) {
      g.fillStyle = dim;
      g.textAlign = "center";
      g.fillText("no aircraft with a position", W / 2, H / 2);
      set("adsb-plot-note", "");
      return;
    }
    var la0 = 90, la1 = -90, lo0 = 180, lo1 = -180;
    pts.forEach(function (p) {
      la0 = Math.min(la0, p[1]); la1 = Math.max(la1, p[1]);
      lo0 = Math.min(lo0, p[2]); lo1 = Math.max(lo1, p[2]);
    });
    var lac = (la0 + la1) / 2, loc = (lo0 + lo1) / 2, k = Math.cos(lac * Math.PI / 180);
    // At least 0.2 deg across so one aircraft is not a full-screen dot.
    var spanY = Math.max(0.2, la1 - la0), spanX = Math.max(0.2 / Math.max(k, 0.1), lo1 - lo0) * k;
    var pad = 24, sc = Math.min((W - 2 * pad) / spanX, (H - 2 * pad) / spanY);
    function X(lon) { return W / 2 + (lon - loc) * k * sc; }
    function Y(lat) { return H / 2 - (lat - lac) * sc; }
    // The scale bar: a round number of km near a fifth of the width.
    var kmPerPx = 111.32 / sc, want = W / 5 * kmPerPx, step = Math.pow(10, Math.floor(Math.log(want) / Math.LN10));
    var km = want / step >= 5 ? 5 * step : want / step >= 2 ? 2 * step : step;
    g.strokeStyle = dim; g.fillStyle = dim; g.lineWidth = 1;
    g.beginPath(); g.moveTo(10, H - 10); g.lineTo(10 + km / kmPerPx, H - 10); g.stroke();
    g.textAlign = "left";
    g.fillText(km + " km", 10, H - 14);
    g.fillText("N↑", W - 24, 14);
    if (rec.length) {
      g.setLineDash([4, 3]);
      g.lineWidth = 1.5;
      for (var ri = 1; ri < rec.length; ri++) {
        var ra = num(rec[ri][3]) ? Math.max(0, rec[ri][3]) : 0;
        g.strokeStyle = heatColor(ra / ALT_SPAN);
        g.beginPath(); g.moveTo(X(rec[ri - 1][2]), Y(rec[ri - 1][1])); g.lineTo(X(rec[ri][2]), Y(rec[ri][1])); g.stroke();
      }
      g.setLineDash([]);
      if (!(j.rows || []).some(function (a) { return a.hex === sel && num(a.lat); })) {
        var lp = rec[rec.length - 1];
        g.fillStyle = dim;
        g.beginPath(); g.arc(X(lp[2]), Y(lp[1]), 4, 0, Math.PI * 2); g.fill();
        g.fillText(sel + " (recorded)", X(lp[2]) + 7, Y(lp[1]) - 6);
      }
    }
    (j.rows || []).forEach(function (a) {
      // Another host's aircraft: its last position only, grey, no
      // altitude colour, named by its host; no track.
      if (remote(a)) {
        if (!num(a.lat)) return;
        var rx = X(a.lon), ry = Y(a.lat);
        g.globalAlpha = 1;
        g.fillStyle = dim; g.strokeStyle = dim;
        g.beginPath(); g.arc(rx, ry, sel === a.hex ? 5 : 3, 0, Math.PI * 2); g.stroke();
        g.textAlign = "left";
        g.fillText(label(a) + " · " + fvName(a), rx + 7, ry - 6);
        return;
      }
      var tp = a.track_pts || [];
      var gone = a.state === "gone", picked = sel === a.hex;
      g.globalAlpha = gone ? 0.35 : 1;
      g.lineWidth = picked ? 2.5 : 1.2;
      for (var i = 1; i < tp.length; i++) {
        var alt = num(tp[i][3]) ? Math.max(0, tp[i][3]) : 0;
        g.strokeStyle = heatColor(alt / ALT_SPAN);
        g.beginPath(); g.moveTo(X(tp[i - 1][2]), Y(tp[i - 1][1])); g.lineTo(X(tp[i][2]), Y(tp[i][1])); g.stroke();
      }
      if (!num(a.lat)) { g.globalAlpha = 1; return; }
      var x = X(a.lon), y = Y(a.lat), aa = altOf(a);
      var col = a.on_ground ? dim : heatColor(num(aa) ? Math.max(0, aa) / ALT_SPAN : 0);
      g.fillStyle = col; g.strokeStyle = col;
      g.beginPath(); g.arc(x, y, picked ? 5 : 3.5, 0, Math.PI * 2); g.fill();
      if (num(a.track)) {
        var t = (a.track - 90) * Math.PI / 180;
        g.lineWidth = 1.5;
        g.beginPath(); g.moveTo(x, y); g.lineTo(x + 12 * Math.cos(t), y + 12 * Math.sin(t)); g.stroke();
      }
      if (emerg(a) || SPECIAL[a.squawk]) {
        g.strokeStyle = cssVar("--heat-3", "#f00");
        g.beginPath(); g.arc(x, y, 9, 0, Math.PI * 2); g.stroke();
      }
      g.fillStyle = cssVar("--ink", "currentColor");
      g.textAlign = "left";
      g.fillText(label(a) + (num(aa) && !a.on_ground ? " " + Math.round(aa / 100) : ""), x + 7, y - 6);
      g.globalAlpha = 1;
    });
    set("adsb-plot-note", "about " + Math.round(spanY * 111) + " km north to south");
  }

  function load() {
    var my = ++gen;
    // This site: fleet=0, the panel's own answer; All sites: the server's default.
    getJSON("/api/adsb" + fvq().replace(/^&/, "?")).then(function (j) {
      if (my !== gen || !visible()) return;
      if (j.out_of_scope) return;
      last = j;
      rows = (j.rows || []).slice();
      header(j);
      drawRows();
      plot(j);
      if (sel) {
        var cur = rows.filter(function (a) { return a.hex === sel; })[0];
        if (cur) (remote(cur) ? remoteDetail : detail)(cur, num(j.now) ? j.now : Math.floor(Date.now() / 1000));
      }
    }).catch(function (e) {
      if (my !== gen) return;
      set("adsb-head", "ADS-B: " + (e && e.message ? e.message : "error"));
    });
  }

  // ── history: sloth.db's adsb_aircraft and adsb_sightings ─────────
  // (web_rfhist.h) Every aircraft seen over a window, a page at a time,
  // and one aircraft's recorded sightings: its altitude profile here and
  // its track (dashed) on the positions plot. Read once a minute.
  var SEEN_MS = 60000, SEEN_PAGE = 100, seenAt = 0, seenGen = 0, histGen = 0;
  var histHex = null, histPts = [], ST = null, seenRows = [], seenLast = null, seenMore = false;
  function when(ts) {
    if (!num(ts) || ts <= 0) return "-";
    var d = new Date(ts * 1000), p = function (n) { return (n < 10 ? "0" : "") + n; };
    return (d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
  }
  var SEEN_COLS = [
    { k: "hx", label: "HEX", w: 8, min: 6, type: "text", val: function (a) { return a.hex; } },
    { k: "fl", label: "FLIGHT", w: 9, min: 4, type: "text", val: function (a) { return a.flight || ""; } },
    { k: "sq", label: "SQWK", w: 5, min: 4, type: "text", val: function (a) { return a.squawk || ""; } },
    { k: "ct", label: "CAT", w: 4, min: 3, type: "text", val: function (a) { return a.category || ""; } },
    { k: "fs", label: "FIRST", w: 11, min: 5, type: "time", val: val("first_seen") },
    { k: "ls", label: "LAST", w: 11, min: 5, type: "time", val: val("last_seen") },
    { k: "vi", label: "VISITS", w: 6, min: 3, num: true, type: "num", val: val("visits") },
    { k: "si", label: "SIGHTINGS", w: 9, min: 4, num: true, type: "num", val: val("sightings") },
    { k: "al", label: "ALT ft", w: 13, min: 5, num: true, type: "num", val: val("alt_max") },
    { k: "gs", label: "GS MAX", w: 7, min: 4, num: true, type: "num", val: val("gs_max") },
    { k: "rs", label: "RSSI MAX", w: 8, min: 4, num: true, type: "num", val: val("rssi_max") },
    { k: "em", label: "EMERG", w: 6, min: 3, type: "text", val: function (a) { return a.emergency_seen ? "yes" : ""; } }
  ];
  function seenTable() {
    if (ST || !window.SlothTables || !$("adsb-seen-box")) return ST;
    ST = window.SlothTables.make({ id: "adsb-seen", label: "aircraft seen", box: $("adsb-seen-box"),
      head: $("adsb-seen-thead"), reset: $("adsb-seen-tools"), redraw: drawSeen, cols: SEEN_COLS });
    return ST;
  }
  function drawSeen() {
    var j = seenLast;
    if (!j) return;
    var t = seenTable();
    var ordered = t ? t.sort(seenRows, true) : seenRows.slice();
    var body = clear($("adsb-seen-rows"));
    set("adsb-seen-count", j.have === false ? "sloth.db has no adsb_aircraft yet (sloth 12+ with --db and --adsb)" :
      seenRows.filter(function (a) { return !remote(a); }).length + (seenMore ? "+" : "") + " in " +
      (j.days === 1 ? "24 h" : j.days + " days") + (j.q ? " matching " + j.q : "") +
      (seenRows.some(remote) ? ", " + seenRows.filter(remote).length + " heard only by other sloth hosts (grey)" : ""));
    $("adsb-seen-more").hidden = !seenMore;
    ordered.forEach(function (a) {
      if (remote(a)) { body.appendChild(seenRemote(a)); return; }
      var r = el("div", "histrow dt-row d-normal" + (histHex === a.hex ? " on" : ""));
      r.appendChild(cell("c-hx", a.hex));
      var plus = fvMark(a);
      if (plus) r.firstChild.appendChild(plus);
      r.appendChild(cell("c-fl" + (a.emergency_seen ? " h3" : ""), a.flight || "-"));
      r.appendChild(cell("c-sq" + (SPECIAL[a.squawk] ? " h3" : ""), a.squawk || "-"));
      r.appendChild(cell("c-ct", a.category || "-"));
      r.appendChild(cell("c-fs d-dim", when(a.first_seen)));
      r.appendChild(cell("c-ls", when(a.last_seen)));
      r.appendChild(cell("c-vi n", a.visits));
      r.appendChild(cell("c-si n", a.sightings));
      r.appendChild(cell("c-al n " + (num(a.alt_max) ? heatClass(Math.max(0, a.alt_max) / ALT_SPAN) : "d-dim"),
        num(a.alt_min) ? (a.alt_min === a.alt_max ? String(a.alt_max) : a.alt_min + "-" + a.alt_max) : "-"));
      r.appendChild(cell("c-gs n", fx(a.gs_max, 0)));
      r.appendChild(cell("c-rs n " + (num(a.rssi_max) ? heatClass(rssiFrac(a.rssi_max)) : "d-dim"), fx(a.rssi_max, 1)));
      r.appendChild(cell("c-em" + (a.emergency_seen ? " h3" : ""), a.emergency_seen ? "yes" : "-"));
      r.tabIndex = 0;
      function pick() {
        sel = a.hex;
        var live = (rows || []).filter(function (x) { return x.hex === a.hex; })[0];
        if (live) (remote(live) ? remoteDetail : detail)(live, num(last && last.now) ? last.now : Math.floor(Date.now() / 1000));
        else histOnly(a);
        drawRows();
        histLoad(a.hex);
      }
      r.addEventListener("click", pick);
      r.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
      body.appendChild(r);
    });
  }
  // An address only another sloth host listed in the window: grey, its
  // host named; the counts and ranges only sloth.db here holds are "-".
  function seenRemote(a) {
    var r = el("div", "histrow dt-row remote" + (histHex === a.hex ? " on" : ""));
    var hx = cell("c-hx", a.hex);
    var fm = fvMark(a);
    if (fm) hx.appendChild(fm);
    r.appendChild(hx);
    r.appendChild(cell("c-fl", a.flight || "-"));
    r.appendChild(cell("c-sq", a.squawk || "-"));
    r.appendChild(cell("c-ct", a.category || "-"));
    r.appendChild(cell("c-fs", when(a.first_seen)));
    r.appendChild(cell("c-ls", when(a.last_seen)));
    r.appendChild(cell("c-vi n", "-"));
    r.appendChild(cell("c-si n", "-"));
    r.appendChild(cell("c-al n", num(a.alt) ? String(a.alt) : "-"));
    r.appendChild(cell("c-gs n", "-"));
    r.appendChild(cell("c-rs n", "-"));
    r.appendChild(cell("c-em", "-"));
    r.tabIndex = 0;
    function pick() {
      sel = a.hex;
      var live = (rows || []).filter(function (x) { return x.hex === a.hex; })[0];
      if (live && remote(live)) remoteDetail(live, num(last && last.now) ? last.now : Math.floor(Date.now() / 1000));
      else if (live) detail(live, num(last && last.now) ? last.now : Math.floor(Date.now() / 1000));
      else histOnly(a);
      drawRows();
      histLoad(a.hex);
    }
    r.addEventListener("click", pick);
    r.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
    return r;
  }
  function seenDays() { var s = $("adsb-seen-days"); return s ? s.value : "7"; }
  function seenQ() { var q = $("adsb-seen-q"); return q ? q.value.trim() : ""; }
  function loadSeen(more) {
    var my = ++seenGen;
    seenAt = Date.now();
    var off = more ? seenRows.length : 0, q = seenQ();
    if (q && !/^~?[0-9A-Za-z]{1,8}$/.test(q)) { set("adsb-seen-count", "search: letters and digits only"); return; }
    getJSON("/api/adsb/seen?days=" + encodeURIComponent(seenDays()) + "&limit=" + SEEN_PAGE +
            "&offset=" + off + (q ? "&q=" + encodeURIComponent(q) : "") + fvq()).then(function (j) {
      if (my !== seenGen) return;
      if (j.out_of_scope) return;
      seenLast = j;
      seenRows = (more ? seenRows : []).concat(j.aircraft || []);
      seenMore = !!j.more;
      drawSeen();
    }).catch(function (e) {
      if (my !== seenGen) return;
      set("adsb-seen-count", "history unavailable: " + (e && e.message ? e.message : "error") + " (needs --sloth-db)");
    });
  }
  // An aircraft the decoder no longer lists: the detail panel from its
  // inventory row alone.
  function histOnly(a) {
    $("adsb-detail").hidden = false;
    set("adsb-detail-name", (a.flight || a.hex) + (a.flight ? " (" + a.hex + ")" : "") +
      (remote(a) ? ", heard by " + (a.sites || []).map(fvName).join(", ") : ", not listed now"));
    clear($("adsb-detail-kv"));
  }
  function histLoad(hex) {
    histHex = hex;
    histPts = [];
    var my = ++histGen;
    set("adsb-hist-note", "loading");
    getJSON("/api/adsb/aircraft?hex=" + encodeURIComponent(hex) + "&days=" + encodeURIComponent(seenDays()) +
            fvq()).then(function (j) {
      if (my !== histGen || j.out_of_scope) return;
      histPts = j.sightings || [];
      var a = j.aircraft, kv = clear($("adsb-hist-kv"));
      if (!a) {
        set("adsb-hist-note", j.fleet && j.fleet.remote && typeof j.fleet.note === "string"
          ? "nothing recorded here: " + j.fleet.note
          : j.have === false ? "sloth.db has no adsb_aircraft yet" : "not in sloth.db yet");
      } else {
        set("adsb-hist-note", histPts.length + " recorded sightings in " + (j.days === 1 ? "24 h" : j.days + " days"));
        [["first seen", when(a.first_seen)],
         ["last seen", when(a.last_seen)],
         ["visits", String(a.visits) + (a.visits > 1 ? " (came back after expiring)" : "")],
         ["sightings recorded", String(a.sightings)],
         ["last callsign", a.flight || "-"],
         ["last squawk", a.squawk || "-"],
         ["category", a.category || "-"],
         ["altitude range", num(a.alt_min) ? a.alt_min + " to " + a.alt_max + " ft" : "-"],
         ["top ground speed", num(a.gs_max) ? a.gs_max.toFixed(0) + " kt" : "-"],
         ["strongest signal", num(a.rssi_max) ? a.rssi_max.toFixed(1) + " dBFS" : "-"],
         ["position ever reported", a.pos_seen ? "yes" : "no"],
         ["emergency ever reported", a.emergency_seen ? "yes" : "no"],
         ["decoder source", a.source_type || "-"]
        ].forEach(function (p) {
          kv.appendChild(el("dt", "", p[0]));
          kv.appendChild(el("dd", p[0] === "emergency ever reported" && a.emergency_seen ? "h3" : "", p[1]));
        });
        var calls = {}, sqs = {};
        histPts.forEach(function (p) { if (p[10]) calls[p[10]] = 1; if (p[9]) sqs[p[9]] = 1; });
        if (Object.keys(calls).length > 1) { kv.appendChild(el("dt", "", "callsigns")); kv.appendChild(el("dd", "", Object.keys(calls).join(", "))); }
        if (Object.keys(sqs).length > 1) { kv.appendChild(el("dt", "", "squawks")); kv.appendChild(el("dd", "", Object.keys(sqs).join(", "))); }
      }
      fleetLines(kv, j.fleet);
      profile(histPts);
      drawSeen();
      plot(last);
    }).catch(function (e) {
      if (my !== histGen) return;
      set("adsb-hist-note", "history unavailable: " + (e && e.message ? e.message : "error"));
    });
  }
  // Altitude over the recorded sightings, heat-graded; ground at the floor.
  function profile(pts) {
    var c = $("adsb-prof");
    if (!c) return;
    var dpr = window.devicePixelRatio || 1, W = Math.max(200, c.clientWidth || 400), H = 160;
    c.width = W * dpr; c.height = H * dpr;
    var g = c.getContext("2d");
    if (!g) return;
    g.scale(dpr, dpr);
    g.clearRect(0, 0, W, H);
    var dim = cssVar("--tui-dim", "#888");
    g.font = "11px monospace"; g.fillStyle = dim;
    var ap = pts.filter(function (p) { return num(p[2]); });
    if (!ap.length) { g.fillText("no recorded altitude", 4, 14); return; }
    var top = Math.max(1000, Math.max.apply(null, ap.map(function (p) { return p[2]; })) * 1.1);
    var t0 = pts[0][0], t1 = pts[pts.length - 1][0], span = Math.max(1, t1 - t0);
    function X(ts) { return pts.length === 1 ? W - 4 : 30 + (ts - t0) / span * (W - 36); }
    function Y(alt) { return H - 14 - Math.max(0, alt) / top * (H - 24); }
    g.fillText(Math.round(top / 100) * 100 + " ft", 2, 12);
    g.fillText(when(t0), 30, H - 2);
    g.textAlign = "right"; g.fillText(when(t1), W - 4, H - 2); g.textAlign = "left";
    g.lineWidth = 1.5;
    var px = null, py = null, pt = null;
    ap.forEach(function (p) {
      var x = X(p[0]), y = Y(p[2]);
      g.strokeStyle = g.fillStyle = heatColor(Math.max(0, p[2]) / ALT_SPAN);
      // A gap over twice the heartbeat is a separate visit: no line across it.
      if (px !== null && p[0] - pt <= 600) { g.beginPath(); g.moveTo(px, py); g.lineTo(x, y); g.stroke(); }
      g.fillRect(x - 1.5, y - 1.5, 3, 3);
      if (SPECIAL[p[9]] || (p[11] && p[11] !== "none")) {
        g.strokeStyle = cssVar("--heat-3", "#f00");
        g.beginPath(); g.arc(x, y, 5, 0, Math.PI * 2); g.stroke();
      }
      px = x; py = y; pt = p[0];
    });
  }

  // Another module's pick (radar.js): the row selected as a click would
  // select it; a row not listed yet is applied by the next load().
  function select(hex) {
    if (typeof hex !== "string" || !/^~?[0-9a-f]{6}$/.test(hex)) return;
    sel = hex;
    var cur = rows.filter(function (a) { return a.hex === hex; })[0];
    if (cur) (remote(cur) ? remoteDetail : detail)(cur, num(last && last.now) ? last.now : Math.floor(Date.now() / 1000));
    drawRows();
    histLoad(hex);
    if (last) plot(last);
  }
  function show() {
    if (!$("v-adsb")) return;
    load();
    if (Date.now() - seenAt > SEEN_MS) loadSeen(false);
    if (!timer) timer = setInterval(function () {
      if (!visible()) return;
      load();
      if (Date.now() - seenAt > SEEN_MS && !seenMore) loadSeen(false);
    }, POLL_MS);
  }
  var seenDaysSel = $("adsb-seen-days");
  if (seenDaysSel) seenDaysSel.addEventListener("change", function () { loadSeen(false); if (histHex) histLoad(histHex); });
  var seenQIn = $("adsb-seen-q"), qTimer = 0;
  if (seenQIn) seenQIn.addEventListener("input", function () {
    clearTimeout(qTimer);
    qTimer = setTimeout(function () { loadSeen(false); }, 300);
  });
  var seenMoreBtn = $("adsb-seen-more");
  if (seenMoreBtn) seenMoreBtn.addEventListener("click", function () { loadSeen(true); });

  var closeBtn = $("adsb-detail-close");
  if (closeBtn) closeBtn.addEventListener("click", closeDetail);

  // app.js's helpers, lent once: go() for the alert link.
  function init(h) { H = h; }

  // The sites choice changed (app.js): every list asked again.
  function refresh() {
    if (!$("v-adsb")) return;
    load();
    loadSeen(false);
    if (histHex) histLoad(histHex);
  }

  window.SlothAdsb = { init: init, show: show, select: select, refresh: refresh };
})();
