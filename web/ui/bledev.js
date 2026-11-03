// slothweb: the BLE Devices view's waterfall (2026-11-02, web_bledev.h,
// owner: "show a waterfall similar to wifi for bluetooth devices";
// "visualize in the best way to convey ble in a similar style").
// window.SlothBleDev, four hooks app.js calls:
//   SlothBleDev.init(h)       once, main()'s helpers lent
//   SlothBleDev.show()        when the BLE view shows: the strip and
//                             both panels, kept current while visible
//   SlothBleDev.drawer(d, n)  when the BLE drawer has a row: its signal
//                             over the waterfall's window, its class,
//                             the LL channels it was heard on
//   SlothBleDev.reset()       when the BLE drawer opens on an address:
//                             the last one's chart and lines cleared,
//                             its series answer, if late, dropped
// An HCI advertising report carries no channel, so the WiFi view's
// channel rows would be one row of -1 here. The two panels say what BLE
// does carry: who is around (device classes by time, each cell the
// class's busiest advertisers as stacked bands, the WiFi channel mix's
// idiom) and how close (one row per advertiser, each cell its mean
// signal graded by the distance band sloth's estimator would give it).
// Same-origin relative paths only, through the page's scoped getJSON;
// every peer string (a name, an address) drawn with fillText or set
// with textContent.
(function () {
  "use strict";
  var H = null;
  var REFRESH_MS = 30000;
  var S = { gen: 0, timer: 0, cls: null, mix: null, prox: null, rows: [], prows: [],
            cur: null, pcur: null, geo: null, pgeo: null, sensor: null };

  // web_bledev.c web_ble_classes[], display order (test_bledev.c holds
  // the two equal, row by row).
  var CLASSES = [
    { slug: "b:phone", label: "Phones & computers", glyph: "P" },
    { slug: "b:wear", label: "Wearables & audio", glyph: "W" },
    { slug: "b:tag", label: "Trackers", glyph: "T" },
    { slug: "b:hid", label: "Input", glyph: "H" },
    { slug: "b:bcn", label: "Beacons", glyph: "B" },
    { slug: "b:iot", label: "Vehicles & IoT", glyph: "I" },
    { slug: "b:unk", label: "Unknown", glyph: "?" }
  ];
  var CLASS_OF = {};
  CLASSES.forEach(function (c, i) { CLASS_OF[c.slug] = i; });
  function classDef(slug) {
    return Object.prototype.hasOwnProperty.call(CLASS_OF, slug) ? CLASSES[CLASS_OF[slug]] : CLASSES[6];
  }

  // src/rf_distance.c for an advertiser announcing no power: P_tx 0 dBm,
  // L(1 m) = 20 log10(2440) - 28 dB, N = 2.8; the band edges at 1, 3, 10
  // and 30 m (web_bledev.c web_ble_prox_edge(), held equal by the test).
  var PROX_L1 = 20 * Math.log10(2440) - 28, PROX_N_X10 = 28, PROX_PTX = 0;
  function proxEdge(m) { return PROX_PTX - (PROX_L1 + PROX_N_X10 * Math.log10(m)); }
  var PROX_EDGES = [proxEdge(1), proxEdge(3), proxEdge(10), proxEdge(30)];
  // A row that announces its power is graded with it (the server's
  // per-row "edges", web_ble_prox_edge_at()); the 0 dBm edges otherwise.
  function edgesAt(ptx) {
    if (!num(ptx)) return PROX_EDGES;
    return PROX_EDGES.map(function (e) { return e + ptx; });
  }
  function rowEdges(r) {
    if (r && Array.isArray(r.edges) && r.edges.length === 4 && r.edges.every(num)) return r.edges;
    return edgesAt(r ? r.ptx : null);
  }
  var PROX_WORD = ["", "immediate", "near", "room", "building", "far"];
  var PROX_SPAN = ["", "under 1 m", "1 to 3 m", "3 to 10 m", "10 to 30 m", "over 30 m"];
  function proxBand(v, E) {
    if (!E) E = PROX_EDGES;
    return v > E[0] ? 1 : v > E[1] ? 2 : v > E[2] ? 3 : v > E[3] ? 4 : 5;
  }
  var PTX_WORD = { ble_ext_tx_power: "announced, extended header", ble_ad_tx_power: "announced, TX Power Level",
                   assumed: "assumed" };
  function ptxText(ptx, src) {
    return (num(ptx) ? ptx : 0) + " dBm " + (Object.prototype.hasOwnProperty.call(PTX_WORD, src) ? PTX_WORD[src] : "assumed");
  }
  // Hot is near: immediate peak, near high, room mid, building cool,
  // far the faint ink, dimmer than the coolest heat; not heard, the
  // page's own ground.
  function proxColor(b) {
    var T = H.theme();
    return b === 1 ? T.heat[3] : b === 2 ? T.heat[2] : b === 3 ? T.heat[1] : b === 4 ? T.heat[0] : T.faint;
  }

  function $(id) { return document.getElementById(id); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); return n; }
  function visible() { var v = $("v-ble"); return v && !v.hidden && !v.classList.contains("scoped-out"); }
  function win() {
    var w = Number($("bledev-win").value) || 3600;
    var now = Math.floor(Date.now() / 1000);
    var to = now - now % 10 + 10;
    return { from: to - w, to: to, win: w };
  }
  function shortAddr(a) { return typeof a === "string" ? a.slice(9) : "?"; }
  // A device's own colour: a named one by its name's hash, as an AP by
  // its SSID's; else by its address (rotating addresses rotate colour).
  function devColor(name, id) {
    var nm = typeof name === "string" && name !== "" ? name : String(id);
    return H.keyColor(nm);
  }

  // ── the sensor: which BLE receivers sloth runs ───────────────────
  // From "now".sensor (sloth's latest sensor_health): none at all is
  // its own state, not a listening sensor that heard no trackers; an
  // Ubertooth alone sends only one-channel samples, which the class
  // mix and ble.class.adv do not credit.
  function noSensor() {
    var s = S.sensor;
    return !!(s && s.seen && !s.btmon_iface && !s.btcap_iface);
  }
  function captureOnly() {
    var s = S.sensor;
    return !!(s && s.seen && !s.btmon_iface && s.btcap_iface);
  }
  function takeSensor(n) { if (n && n.sensor && typeof n.sensor === "object") S.sensor = n.sensor; }
  function emptyState() {
    var none = noSensor();
    ["bledev-classes", "bledev-prox", "bledev-prox-legend"].forEach(function (id) { $(id).hidden = none; });
    if (!none) return false;
    var line = clear($("bledev-now"));
    line.appendChild(H.el("span", "d-dim", "(no BLE sensor: no advertisements decoded - start with --bt-monitor or " +
                          "--bt-capture PATH; see docs/wiki/ble.md. sloth never scans, connects or reads GATT.)"));
    H.set("bledev-classes-note", "");
    H.set("bledev-mix-note", "");
    H.set("bledev-prox-note", "");
    clear($("bledev-detail"));
    clear($("bledev-pdetail"));
    S.geo = S.pgeo = null;
    return true;
  }

  // ── the strip: what is here now ──────────────────────────────────
  function nowLine(n) {
    takeSensor(n);
    if (emptyState()) return;
    var line = clear($("bledev-now"));
    if (!n) return;
    line.appendChild(H.el("span", "d-normal", "BLE now (last " + n.window_s + " s): "));
    line.appendChild(H.el("span", "d-bright", String(n.advertisers) + (n.advertisers_more ? "+" : "")));
    line.appendChild(H.el("span", "d-normal", " advertiser" + (n.advertisers === 1 ? "" : "s") + ", trackers "));
    line.appendChild(H.el("span", n.trackers > 0 ? "h2" : "d-dim", String(n.trackers)));
    line.appendChild(H.el("span", "d-normal", ", nearest "));
    var ne = n.nearest;
    if (ne) {
      var who = H.el("span", "d-bright", ne.name !== null ? "\"" + ne.name + "\"" : classDef(ne["class"]).label + " " + shortAddr(ne.addr));
      line.appendChild(who);
      line.appendChild(H.el("span", "d-normal", " " + ne.rssi + " dBm " + (ne.band ? ne.band + " (sloth's est.)" : ne.grade + " (grade)") +
                            (ne.ptx_source && ne.ptx_source !== "assumed" ? ", P_tx " + ptxText(ne.ptx, ne.ptx_source) : "")));
    } else {
      line.appendChild(H.el("span", "d-dim", "-"));
    }
    line.appendChild(H.el("span", "d-normal", ", "));
    line.appendChild(H.el("span", "d-bright", num(n.adv_rate) ? H.fmt(n.adv_rate) : "-"));
    line.appendChild(H.el("span", "d-normal", " reports/s" + (captureOnly() ? " (the host stream's; --bt-capture only: none)" : "")));
  }

  // ── panel A: who is around ───────────────────────────────────────
  function classRows() {
    var by = {}, out = [];
    function add(r) {
      var k = String(r.key);
      if (!Object.prototype.hasOwnProperty.call(CLASS_OF, k)) return null;
      if (!by[k]) { by[k] = { key: k, heat: null, mix: null }; out.push(by[k]); }
      return by[k];
    }
    ((S.cls && S.cls.rows) || []).forEach(function (r) { var e = add(r); if (e) e.heat = r; });
    ((S.mix && S.mix.rows) || []).forEach(function (r) { var e = add(r); if (e) e.mix = r; });
    // Trackers always: an empty Trackers row is information.
    add({ key: "b:tag" });
    out.sort(function (a, b) { return CLASS_OF[a.key] - CLASS_OF[b.key]; });
    return out;
  }
  function rowBusy(r) {
    if (!r.heat || !r.heat.cells) return 0;
    var s = 0, n = 0;
    r.heat.cells.forEach(function (v) { if (num(v)) { s += v; n++; } });
    if (!n) return 0;
    return S.cls.kind === "gauge" ? s / n : s;
  }
  function txOf(i) {
    var t = S.mix && S.mix.tx && S.mix.tx[i];
    return t && typeof t.id === "string" ? t : null;
  }
  // Anonymous advertising (an extended advertisement with no AdvA; one
  // entry, kind "anon", in Unknown alone) is no device: neutral, not a
  // hash hue that would read as one advertiser, and not the rest's grey.
  function isAnon(t) { return !!t && t.kind === "anon"; }
  function txColor(t) {
    if (isAnon(t)) return H.theme().muted;
    return t ? devColor(t.name, t.id) : H.theme().heat[0];
  }

  function classGrid() {
    if (emptyState()) return;
    var c = $("bledev-classes"), T = H.theme();
    var dpr = H.sizeCanvas(c), g = c.getContext("2d");
    var W = c.width, Hh = c.height;
    g.clearRect(0, 0, W, Hh);
    g.fillStyle = T.bg;
    g.fillRect(0, 0, W, Hh);
    var rows = classRows();
    S.rows = rows;
    var src = S.mix || S.cls;
    var cols = src && num(src.cols) ? src.cols : 0, col_s = src ? src.col_s : 0, from = src ? src.from : 0;
    S.geo = null;
    if (S.cls) H.set("bledev-classes-note", rows.length + " classes, " + S.cls.tier + " tier, " + H.fmt(S.cls.col_s) + " s cells");
    if (S.mix) {
      var txs = S.mix.tx || [], named = txs.filter(function (t) { return !isAnon(t); }).length;
      H.set("bledev-mix-note", named + " advertisers named" +
            (named < txs.length ? " and anonymous advertising (no address: one neutral band, in Unknown)" : "") +
            ", " + S.mix.source +
            (S.mix.folded ? "; some folded into other" : "") +
            (num(S.mix.ring_from) && S.mix.ring_from > from ? "; detail held from " + H.hhmmss(S.mix.ring_from) : "") +
            (captureOnly() ? "; --bt-capture only: an Ubertooth's one-channel samples are not credited, so there is no " +
                             "advertiser detail and no report count, and the cells are advertiser counts only" : ""));
    }
    if (!rows.length || !cols) { classDetail(); return; }
    var busy = rows.map(rowBusy), bmax = 0, hmax = 0;
    busy.forEach(function (v) { if (v > bmax) bmax = v; });
    rows.forEach(function (r) {
      ((r.heat && r.heat.cells) || []).forEach(function (v) { if (num(v) && v > hmax) hmax = v; });
    });
    var rh = Math.max(4 * dpr, Math.floor((Hh - 2 * dpr) / rows.length));
    g.font = Math.min(11 * dpr, rh) + "px " + H.css("--font-mono");
    g.textBaseline = "middle";
    // At phone width the full label would take half the canvas: past
    // 30% of it the row carries its glyph alone (the legend says which).
    var padL = 0, glyphOnly = false;
    function lab(r) { var d = classDef(r.key); return glyphOnly ? d.glyph : d.glyph + " " + d.label; }
    rows.forEach(function (r) { var w = g.measureText(lab(r)).width; if (w > padL) padL = w; });
    if (padL + 6 * dpr > W * 0.3) {
      glyphOnly = true;
      padL = 0;
      rows.forEach(function (r) { var w = g.measureText(lab(r)).width; if (w > padL) padL = w; });
    }
    padL += 6 * dpr;
    var strip = 6 * dpr, x0 = padL + strip + 2 * dpr, cw = (W - x0) / Math.max(1, cols);
    S.geo = { x0: x0, rh: rh, cw: cw, cols: cols, col_s: col_s, from: from, dpr: dpr };
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i], y = i * rh, d = classDef(r.key);
      g.fillStyle = r.key === "b:tag" ? T.signal : T.muted;
      g.fillText(lab(r), 2 * dpr, y + rh / 2);
      g.fillStyle = busy[i] > 0 ? H.heat(bmax > 0 ? busy[i] / bmax : 0) : T.rule;
      g.fillRect(padL, y + dpr, strip, rh - dpr);
      g.fillStyle = T.rule;
      g.fillRect(x0, y + rh - Math.max(1, dpr / 2), W - x0, Math.max(1, dpr / 2));
      for (var k = 0; k < cols; k++) {
        var x = x0 + k * cw, w = Math.max(dpr, Math.ceil(cw) - (cw > 3 * dpr ? dpr : 0));
        var m = r.mix && r.mix.cells ? r.mix.cells[k] : null;
        if (Array.isArray(m) && num(m[0]) && m[0] > 0) {
          var tot = m[0], yy = y + rh - dpr, hh = rh - 2 * dpr;
          for (var e = 2; e + 1 < m.length; e += 2) {
            var bh = hh * m[e + 1] / tot;
            g.fillStyle = txColor(txOf(m[e]));
            yy -= bh;
            g.fillRect(x, yy, w, bh);
          }
          if (num(m[1]) && m[1] > 0) {
            var oh = hh * m[1] / tot;
            g.fillStyle = T.heat[0];
            yy -= oh;
            g.fillRect(x, yy, w, oh);
          }
          continue;
        }
        var v = r.heat && r.heat.cells ? r.heat.cells[k] : null;
        if (!num(v) || v <= 0) continue;
        g.globalAlpha = 0.45;
        g.fillStyle = H.heat(hmax > 0 ? v / hmax : 0);
        g.fillRect(x, y + dpr, w, rh - 2 * dpr);
        g.globalAlpha = 1;
      }
    }
    var cur = S.cur;
    if (cur && cur.r < rows.length && cur.c < cols) {
      g.strokeStyle = T.signal;
      g.lineWidth = Math.max(1, dpr);
      g.strokeRect(x0 + cur.c * cw + 0.5, cur.r * rh + 0.5, Math.max(dpr, cw - 1), rh - 1);
    }
    classDetail();
  }

  // The list under panel A: the picked cell's advertisers, each a
  // button that opens its drawer, then the rest.
  function classDetail() {
    var box = clear($("bledev-detail")), cur = S.cur, geo = S.geo, rows = S.rows;
    if (!cur || !geo || cur.r >= rows.length || cur.c >= geo.cols) {
      box.appendChild(H.el("div", "sub", "point at, tap or arrow to a cell for who was advertising"));
      return;
    }
    var r = rows[cur.r], t0 = geo.from + cur.c * geo.col_s, d = classDef(r.key);
    var m = r.mix && r.mix.cells ? r.mix.cells[cur.c] : null;
    var hv = r.heat && r.heat.cells ? r.heat.cells[cur.c] : null;
    var head = d.label + "  " + H.hhmmss(t0) + " to " + H.hhmmss(t0 + geo.col_s);
    if (Array.isArray(m) && num(m[0])) head += "  " + H.fmt(m[0]) + " reports";
    if (num(hv)) head += "  (" + (S.cls.metric === "ble.class.adv" ? "reports " : "advertisers ") + H.fmt(hv) + ")";
    box.appendChild(H.el("div", "label", head));
    if (!Array.isArray(m) || !num(m[0]) || m[0] <= 0) {
      box.appendChild(H.el("div", "sub", "no advertiser detail for this cell"));
      return;
    }
    var ol = H.el("ol", "mixl");
    function share(f) { return (100 * f / m[0]).toFixed(f * 1000 < m[0] ? 2 : 1) + "%"; }
    for (var e = 2; e + 1 < m.length; e += 2) {
      var t = txOf(m[e]);
      if (!t) continue;
      var li = H.el("li", "");
      // An address the tables still hold opens its drawer; one they no
      // longer hold (the mix outlives a row) is a line, not a button,
      // and so is the anonymous entry, which has no address to open.
      var anon = isAnon(t);
      var held = !anon && num(t.addr_type) && typeof t.iface === "string";
      var b = H.el(held ? "button" : "span", "mixgo");
      if (held) b.type = "button";
      var sw = H.el("span", "sw");
      sw.style.background = txColor(t);
      b.appendChild(sw);
      var nm = H.el("span", "nm");
      if (anon) {
        nm.appendChild(H.el("span", "d-normal", "anonymous"));
        nm.appendChild(H.el("span", "d-dim", "  extended advertising with no address: every such advertiser a sensor heard, one row of fields between them, so Unknown"));
      } else {
        nm.appendChild(H.el("span", "d-normal", t.name !== null ? "\"" + t.name + "\"" : t.id));
        nm.appendChild(H.el("span", "d-dim", (t.name !== null ? "  " + t.id : "") + "  " +
                            (t["class"] ? classDef(t["class"]).label : "not in the table now")));
      }
      b.appendChild(nm);
      b.appendChild(H.el("span", "n d-bright", H.fmt(m[e + 1])));
      b.appendChild(H.el("span", "n d-normal", share(m[e + 1])));
      if (held) b.addEventListener("click", openOf(t.id, t.addr_type, t.iface));
      li.appendChild(b);
      ol.appendChild(li);
    }
    if (num(m[1]) && m[1] > 0) {
      var lo = H.el("li", ""), row = H.el("span", "mixgo"), so = H.el("span", "sw");
      so.style.background = H.theme().heat[0];
      row.appendChild(so);
      row.appendChild(H.el("span", "nm d-dim", "other advertisers"));
      row.appendChild(H.el("span", "n d-bright", H.fmt(m[1])));
      row.appendChild(H.el("span", "n d-normal", share(m[1])));
      lo.appendChild(row);
      ol.appendChild(lo);
    }
    box.appendChild(ol);
  }

  function openOf(addr, type, iface) {
    return function () { H.openBleDrawer(addr, type, iface); };
  }

  // ── panel B: how close ───────────────────────────────────────────
  var PROW_PX = 14;
  function proxGrid() {
    if (emptyState()) return;
    var c = $("bledev-prox"), T = H.theme();
    var rows = (S.prox && S.prox.rows) || [];
    S.prows = rows;
    c.style.height = Math.max(3, rows.length) * PROW_PX + 4 + "px";
    var dpr = H.sizeCanvas(c), g = c.getContext("2d");
    var W = c.width, Hh = c.height;
    g.clearRect(0, 0, W, Hh);
    g.fillStyle = T.bg;
    g.fillRect(0, 0, W, Hh);
    S.pgeo = null;
    var p = S.prox;
    // candidates is what was read, at most 256: under a cut it is the
    // read, not the window's total, and the note says so.
    if (p) H.set("bledev-prox-note", rows.length + " of " +
                 (p.read_cut ? "the " + p.candidates + " read (every tracker, then the newest; more were heard in the window)"
                             : p.candidates + " advertisers in the window") + ", " +
                 p.tier + " tier, " + H.fmt(p.col_s) + " s cells" + (p.more && !p.read_cut ? "; more than shown" : "") +
                 (p.anonymous_heard ? "; anonymous advertising heard and not drawn: no address to key a signal by " +
                                      "(it is in the class panel)" : ""));
    if (!p || !rows.length || !p.cols) {
      g.fillStyle = T.faint;
      g.fillRect(W * 0.35, Hh / 2, W * 0.3, Math.max(1, dpr));
      proxDetail();
      return;
    }
    var rh = PROW_PX * dpr;
    g.font = Math.min(11 * dpr, rh - 2 * dpr) + "px " + H.css("--font-mono");
    g.textBaseline = "middle";
    var labels = rows.map(function (r) {
      var d = classDef(r["class"]);
      return d.glyph + " " + (r.name !== null ? r.name : "") + (r.name !== null ? " " : "") + shortAddr(r.addr);
    });
    var padL = 0;
    labels.forEach(function (s) { var w = g.measureText(s).width; if (w > padL) padL = w; });
    padL = Math.min(padL + 6 * dpr, W * 0.35);
    var x0 = padL + 2 * dpr, cw = (W - x0) / Math.max(1, p.cols);
    S.pgeo = { x0: x0, rh: rh, cw: cw, cols: p.cols, col_s: p.col_s, from: p.from, dpr: dpr };
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i], y = i * rh;
      g.save();
      g.beginPath();
      g.rect(0, y, padL, rh);
      g.clip();
      g.fillStyle = r["class"] === "b:tag" ? T.signal : T.muted;
      g.fillText(labels[i], 2 * dpr, y + rh / 2);
      g.restore();
      for (var k = 0; k < p.cols; k++) {
        var v = r.cells ? r.cells[k] : null;
        if (!num(v)) continue;
        var x = x0 + k * cw, w = Math.max(dpr, Math.ceil(cw) - (cw > 3 * dpr ? dpr : 0));
        g.fillStyle = proxColor(proxBand(v, rowEdges(r)));
        g.fillRect(x, y + dpr, w, rh - 2 * dpr);
      }
    }
    var cur = S.pcur;
    if (cur && cur.r < rows.length && cur.c < p.cols) {
      g.strokeStyle = T.signal;
      g.lineWidth = Math.max(1, dpr);
      g.strokeRect(x0 + cur.c * cw + 0.5, cur.r * rh + 0.5, Math.max(dpr, cw - 1), rh - 1);
    }
    proxDetail();
  }

  function proxDetail() {
    var box = clear($("bledev-pdetail")), cur = S.pcur, geo = S.pgeo, rows = S.prows;
    if (!cur || !geo || cur.r >= rows.length || cur.c >= geo.cols) {
      box.appendChild(H.el("div", "sub", "point at, tap or arrow to a cell for its signal; click a name for the advertiser"));
      return;
    }
    var r = rows[cur.r], t0 = geo.from + cur.c * geo.col_s, v = r.cells ? r.cells[cur.c] : null, E = rowEdges(r);
    box.appendChild(H.el("div", "label", H.hhmmss(t0) + " to " + H.hhmmss(t0 + geo.col_s) + "  " +
                         (num(v) ? v.toFixed(1) + " dBm mean, " + PROX_WORD[proxBand(v, E)] + " (" + PROX_SPAN[proxBand(v, E)] +
                                   " at P_tx " + ptxText(r.ptx, r.ptx_source) + ")" : "not heard")));
    var ol = H.el("ol", "mixl"), li = H.el("li", ""), b = H.el("button", "mixgo");
    b.type = "button";
    var sw = H.el("span", "sw");
    sw.style.background = num(v) ? proxColor(proxBand(v, E)) : H.theme().rule;
    b.appendChild(sw);
    var nm = H.el("span", "nm");
    nm.appendChild(H.el("span", "d-normal", r.name !== null ? "\"" + r.name + "\"" : r.addr));
    nm.appendChild(H.el("span", "d-dim", (r.name !== null ? "  " + r.addr : "") + "  " + r.addr_kind + "  " +
                        classDef(r["class"]).label + "  " + r.iface + (r.rows > 1 ? "  " + r.rows + " sensors" : "")));
    b.appendChild(nm);
    b.appendChild(H.el("span", "n d-bright", num(r.best) ? r.best + " best" : "-"));
    b.appendChild(H.el("span", "n d-normal", r.samples + " pts"));
    b.addEventListener("click", openOf(r.addr, r.addr_type, r.iface));
    li.appendChild(b);
    ol.appendChild(li);
    box.appendChild(ol);
  }

  function legend() {
    var box = clear($("bledev-prox-legend"));
    for (var b = 1; b <= 5; b++) {
      var it = H.el("span", "bledev-key");
      var sw = H.el("span", "sw");
      sw.style.background = proxColor(b);
      it.appendChild(sw);
      it.appendChild(H.el("span", "d-normal", PROX_WORD[b] + " " + PROX_SPAN[b] +
                          (b < 5 ? " (> " + PROX_EDGES[b - 1].toFixed(1) + " dBm at 0 dBm)" : "")));
      box.appendChild(it);
    }
  }

  // ── picking, as the WiFi grid picks ──────────────────────────────
  function pick(ev, canvas, geo, nrows, which) {
    if (!geo) return;
    var bx = canvas.getBoundingClientRect();
    var px = (ev.clientX - bx.left) * (canvas.width / Math.max(1, bx.width));
    var py = (ev.clientY - bx.top) * (canvas.height / Math.max(1, bx.height));
    var col = Math.floor((px - geo.x0) / geo.cw), row = Math.floor(py / geo.rh);
    if (row < 0 || row >= nrows) return;
    if (col < 0 || col >= geo.cols) return;
    var key = which === "p" ? "pcur" : "cur";
    if (S[key] && S[key].r === row && S[key].c === col) return;
    S[key] = { r: row, c: col };
    if (which === "p") proxGrid(); else classGrid();
  }
  // A name in the label column opens its drawer on a click: a primary
  // press and release without a drag, so a scroll that starts on the
  // canvas, or another button, does not open it.
  function labelClick(ev, canvas, geo) {
    if (!geo || ev.button !== 0) return;
    var bx = canvas.getBoundingClientRect();
    var px = (ev.clientX - bx.left) * (canvas.width / Math.max(1, bx.width));
    var py = (ev.clientY - bx.top) * (canvas.height / Math.max(1, bx.height));
    var row = Math.floor(py / geo.rh);
    if (px >= geo.x0 || row < 0 || row >= S.prows.length) return;
    var r = S.prows[row];
    if (r) H.openBleDrawer(r.addr, r.addr_type, r.iface);
  }
  function keys(ev, geo, nrows, which, detailId) {
    if (!geo || !nrows) return;
    var key = which === "p" ? "pcur" : "cur";
    var cur = S[key] || { r: 0, c: geo.cols - 1 };
    var MOVE = { ArrowLeft: [0, -1], ArrowRight: [0, 1], ArrowUp: [-1, 0], ArrowDown: [1, 0] };
    var d = Object.prototype.hasOwnProperty.call(MOVE, ev.key) ? MOVE[ev.key] : null;
    if (d) {
      ev.preventDefault();
      S[key] = { r: Math.max(0, Math.min(nrows - 1, cur.r + d[0])),
                 c: Math.max(0, Math.min(geo.cols - 1, cur.c + d[1])) };
      if (which === "p") proxGrid(); else classGrid();
      return;
    }
    if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      if (!S[key]) { S[key] = cur; if (which === "p") proxGrid(); else classGrid(); }
      var first = $(detailId).querySelector("button");
      if (first) first.focus();
    }
  }

  // ── loading ──────────────────────────────────────────────────────
  function load() {
    if (!H || !visible()) return;
    var gen = ++S.gen, r = win(), metric = $("bledev-metric").value === "adv" ? "adv" : "advertisers";
    var n = ["12", "24", "48"].indexOf($("bledev-n").value) >= 0 ? $("bledev-n").value : "24";
    var q = "?from=" + r.from + "&to=" + r.to + "&cols=96";
    H.getJSON("/api/ble/classes" + q + "&metric=" + metric).then(function (j) {
      if (gen !== S.gen || j.out_of_scope) return;
      S.cls = j;
      nowLine(j.now);
      classGrid();
    }).catch(function (e) { if (gen === S.gen) H.set("bledev-classes-note", H.errText(e.message)); });
    H.getJSON("/api/ble/classes" + q + "&mix=1").then(function (j) {
      if (gen !== S.gen || j.out_of_scope) return;
      S.mix = j;
      classGrid();
    }).catch(function (e) {
      if (gen !== S.gen) return;
      S.mix = null;
      H.set("bledev-mix-note", H.errText(e.message));
      classGrid();
    });
    H.getJSON("/api/ble/proximity" + q + "&n=" + n).then(function (j) {
      if (gen !== S.gen || j.out_of_scope) return;
      S.prox = j;
      takeSensor(j.now);
      proxGrid();
    }).catch(function (e) { if (gen === S.gen) H.set("bledev-prox-note", H.errText(e.message)); });
  }

  function show() {
    if (!H) return;
    legend();
    load();
    if (!S.timer) S.timer = setInterval(function () { if (visible()) load(); }, REFRESH_MS);
  }

  // ── the drawer: the row's signal over the waterfall's window ─────
  var DR = { gen: 0 };
  function rssiChart(pts, from, to, step, E) {
    if (!E) E = PROX_EDGES;
    var c = $("bledev-rssi"), T = H.theme();
    var dpr = H.sizeCanvas(c), g = c.getContext("2d");
    var W = c.width, Hh = c.height, LO = -100, HI = -20;
    g.clearRect(0, 0, W, Hh);
    function X(t) { return (t - from) / Math.max(1, to - from) * W; }
    function Y(v) { return Hh - (Math.max(LO, Math.min(HI, v)) - LO) / (HI - LO) * Hh; }
    // The band edges, faint, so the line reads against the grade.
    g.fillStyle = T.rule;
    E.forEach(function (e) { g.fillRect(0, Math.round(Y(e)), W, Math.max(1, dpr / 2)); });
    if (!pts.length) {
      g.fillStyle = T.faint;
      g.fillRect(W * 0.35, Hh / 2, W * 0.3, Math.max(1, dpr));
      return;
    }
    g.lineWidth = Math.max(1, 1.5 * dpr);
    for (var i = 1; i < pts.length; i++) {
      if (pts[i][0] - pts[i - 1][0] > 2.5 * step) continue;
      g.strokeStyle = proxColor(proxBand(pts[i][1], E));
      g.beginPath();
      g.moveTo(X(pts[i - 1][0]), Y(pts[i - 1][1]));
      g.lineTo(X(pts[i][0]), Y(pts[i][1]));
      g.stroke();
    }
    var r = Math.max(1.5, 1.5 * dpr);
    pts.forEach(function (p) {
      g.fillStyle = proxColor(proxBand(p[1], E));
      g.fillRect(X(p[0]) - r / 2, Y(p[1]) - r / 2, r, r);
    });
  }
  // The drawer opens on another address (or one that left the table, or
  // the theme changed): nothing of the last one's stays under the new
  // address, and its series answer, if still in flight, is dropped.
  function reset() {
    if (!H) return;
    ++DR.gen;
    var c = $("bledev-rssi");
    var g = c.getContext("2d");
    g.clearRect(0, 0, c.width, c.height);
    H.set("bledev-rssi-note", "");
    H.set("bledev-class", "");
    H.set("bledev-chans", "");
    $("bledev-chans").hidden = true;
  }
  function drawer(d) {
    if (!H) return;
    if (!d || typeof d.addr !== "string") { reset(); return; }
    var gen = ++DR.gen, r = win(), cd = classDef(d["class"]);
    var E = edgesAt(num(d.grade_ptx) ? d.grade_ptx : null);
    H.set("bledev-class", "class: " + cd.label + (typeof d.class_label === "string" && d.class_label !== cd.label ? " (" + d.class_label + ")" : ""));
    var ch = $("bledev-chans");
    ch.hidden = !Array.isArray(d.channels) || !d.channels.length;
    H.set("bledev-chans", Array.isArray(d.channels) && d.channels.length
      ? "heard on LL channel" + (d.channels.length > 1 ? "s " : " ") + d.channels.join(", ") + " since slothweb started (an Ubertooth row; the host controller reports no channel)"
      : "");
    var tier = H.tierFor(r.win);
    H.set("bledev-rssi-note", "loading");
    H.series("rf.rssi.ble", d.addr, tier, r.from, r.to).then(function (s) {
      if (gen !== DR.gen) return;
      var pts = (s.points || []).filter(function (p) { return num(p[1]); }).map(function (p) { return [p[0], p[1]]; });
      rssiChart(pts, r.from, r.to, s.step || 10, E);
      H.set("bledev-rssi-note", pts.length
        ? "rf.rssi.ble, " + (r.win >= 86400 ? Math.round(r.win / 86400) + " d" : Math.round(r.win / 3600) + " h") + ", " + tier +
          " tier, -100 to -20 dBm, n=" + pts.length + "; coloured by the grade at P_tx " +
          ptxText(d.grade_ptx, d.grade_ptx_source) + ", faint lines at its edges"
        : "no data: no signal sample of this address in the window");
    }).catch(function (e) { if (gen === DR.gen) H.set("bledev-rssi-note", H.errText(e.message)); });
  }

  function init(h) {
    H = h;
    var cc = $("bledev-classes"), pc = $("bledev-prox");
    cc.tabIndex = 0;
    pc.tabIndex = 0;
    cc.addEventListener("pointermove", function (ev) { if (ev.pointerType === "mouse") pick(ev, cc, S.geo, S.rows.length, "c"); });
    cc.addEventListener("pointerdown", function (ev) { pick(ev, cc, S.geo, S.rows.length, "c"); });
    cc.addEventListener("keydown", function (ev) { keys(ev, S.geo, S.rows.length, "c", "bledev-detail"); });
    pc.addEventListener("pointermove", function (ev) { if (ev.pointerType === "mouse") pick(ev, pc, S.pgeo, S.prows.length, "p"); });
    pc.addEventListener("pointerdown", function (ev) { pick(ev, pc, S.pgeo, S.prows.length, "p"); });
    pc.addEventListener("click", function (ev) { labelClick(ev, pc, S.pgeo); });
    pc.addEventListener("keydown", function (ev) { keys(ev, S.pgeo, S.prows.length, "p", "bledev-pdetail"); });
    ["bledev-win", "bledev-metric", "bledev-n"].forEach(function (id) {
      $(id).addEventListener("change", function () { S.cur = S.pcur = null; load(); });
    });
    window.addEventListener("resize", function () {
      if (!visible()) return;
      if (S.geo) classGrid();
      if (S.pgeo) proxGrid();
    });
  }

  window.SlothBleDev = { init: init, show: show, drawer: drawer, reset: reset };
})();
