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
            cur: null, pcur: null, geo: null, pgeo: null, sensor: null,
            iso: true, ist: isoState(), pist: isoState() };
  // Each isometric canvas's own picture and hover (web/ui/iso.js).
  function isoState() { return { off: null, dirty: true, geo: null, hover: null, o: null }; }

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
  // The isometric panels' colours (owner 2026-11-17: "color code
  // finding ... easy to tell by color groupings"). BLE reports carry no
  // channel and no SSID, so the grouping is the class: each its own hue
  // (iso.css --iso-c-*, read by SlothIso.scheme() at each draw;
  // Trackers red-orange), its shade steps for what is inside the class.
  // A step is how far from the ground (iso.js paint()'s segment alpha):
  // the busiest advertisers in turn, the rest the darkest; an advertiser
  // on the proximity panel at the step its address's hash picks, so
  // neighbours in a group stay apart (a rotating address may change
  // step, as it changes row).
  var ISO_STEP = [1, 0.78, 0.6, 0.45], ISO_REST = 0.32;
  function classHue(slug, P) { return P.cls[classDef(slug).slug]; }
  function classToken(slug) { return "var(--iso-c-" + classDef(slug).slug.slice(2) + ")"; }
  function addrStep(a) {
    var h = 0, s = String(a);
    for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
    return h % ISO_STEP.length;
  }
  // The proximity panel's advertisers grouped by class, in CLASSES'
  // order, each class keeping the table's order (trackers first, then
  // the nearest).
  function byClass(rows) {
    return rows.map(function (r, i) { return { r: r, i: i, c: CLASS_OF[classDef(r["class"]).slug] }; })
      .sort(function (a, b) { return a.c - b.c || a.i - b.i; })
      .map(function (e) { return e.r; });
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
    ["bledev-cls-key", "bledev-prox-key"].forEach(function (id) { $(id).hidden = none || !S.iso; });
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
    c.style.height = S.iso ? "300px" : "";
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
    if (S.iso) {
      S.geo = rows.length && cols ? { cols: cols, col_s: col_s, from: from, iso: true } : null;
      classIso(rows, cols, col_s, from);
      classDetail();
      return;
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

  // Panel A isometric (#224): the classes across, the time cells
  // receding with the newest in front, each column's height and heat
  // its cell in the cells select (advertisers per class or reports), on
  // one scale, 0 to the window's largest cell.
  function classIso(rows, cols, col_s, from) {
    var hmax = 0;
    rows.forEach(function (r) {
      ((r.heat && r.heat.cells) || []).forEach(function (v) { if (num(v) && v > hmax) hmax = v; });
    });
    var cur = S.cur, P = SlothIso.scheme();
    SlothIso.grid($("bledev-classes"), S.ist, {
      cols: rows.map(function (r) {
        var d = classDef(r.key), hue = classHue(r.key, P);
        return { label: d.glyph + " " + d.label, short: d.glyph, floor: { color: hue }, cap: hue };
      }),
      n: rows.length ? cols : 0, from: from, col_s: col_s,
      value: function (k, i) { var cl = rows[i].heat && rows[i].heat.cells; return cl ? cl[k] : null; },
      segments: function (k, i) { return classSegs(rows[i], k, classHue(rows[i].key, P)); },
      lo: 0, hi: hmax > 0 ? hmax : 1, ticks: hmax > 0 ? [0, hmax / 2, hmax] : [0], unit: classUnit(), fmt: H.fmt,
      clock: H.hhmmss, sel: cur && cur.r < rows.length && cur.c < cols ? { k: cur.c, c: cur.r } : null,
      empty: S.cls ? "no class in the window" : "loading"
    });
  }
  // A class cell's column body, bottom up: its busiest advertisers by
  // share, each a step darker, then the rest darkest; with no
  // advertiser detail, the class's hue whole.
  function classSegs(r, k, hue) {
    var m = r.mix && r.mix.cells ? r.mix.cells[k] : null, out = [];
    if (!Array.isArray(m) || !num(m[0]) || m[0] <= 0) return [{ f: 1, color: hue }];
    for (var e = 2, s = 0; e + 1 < m.length; e += 2, s++)
      out.push({ f: m[e + 1] / m[0], color: hue, alpha: ISO_STEP[Math.min(s, ISO_STEP.length - 1)] });
    if (num(m[1]) && m[1] > 0) out.push({ f: m[1] / m[0], color: hue, alpha: ISO_REST });
    return out.length ? out : [{ f: 1, color: hue }];
  }
  function classUnit() { return S.cls && S.cls.metric === "ble.class.adv" ? "reports" : "advertisers"; }

  function openOf(addr, type, iface) {
    return function () { H.openBleDrawer(addr, type, iface); };
  }

  // ── panel B: how close ───────────────────────────────────────────
  var PROW_PX = 14;
  function proxGrid() {
    if (emptyState()) return;
    var c = $("bledev-prox"), T = H.theme();
    var rows = (S.prox && S.prox.rows) || [];
    // Isometric, the advertisers are grouped by class; the picked
    // advertiser stays picked across the reorder and across a refresh
    // (new row objects, maybe a new order), found by its address, type
    // and sensor, so the hover, the tooltip and the list under the panel
    // name the advertiser they named.
    if (S.iso) rows = byClass(rows);
    var was = S.pcur ? S.prows[S.pcur.r] : null, at = was ? rows.findIndex(function (r) {
      return r === was || (r.addr === was.addr && r.addr_type === was.addr_type && r.iface === was.iface);
    }) : -1;
    if (at >= 0 && at !== S.pcur.r) S.pcur = { r: at, c: S.pcur.c };
    S.prows = rows;
    c.style.height = S.iso ? "320px" : Math.max(3, rows.length) * PROW_PX + 4 + "px";
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
    if (S.iso) {
      S.pgeo = p && rows.length && p.cols ? { cols: p.cols, col_s: p.col_s, from: p.from, iso: true } : null;
      proxIso(rows, p);
      proxDetail();
      return;
    }
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

  // Panel B isometric (#224): the advertisers across in the table's
  // order, the time cells receding, each column's height and heat its
  // mean signal from -110 to -30 dBm (the flat grid's distance bands
  // are in the tooltip and the list, at the row's own power).
  var PROX_LO = -110, PROX_HI = -30;
  function proxIso(rows, p) {
    var cur = S.pcur, cols = p && p.cols ? p.cols : 0, P = SlothIso.scheme();
    var hue = rows.map(function (r) { return classHue(r["class"], P); });
    var step = rows.map(function (r) { return ISO_STEP[addrStep(r.addr)]; });
    SlothIso.grid($("bledev-prox"), S.pist, {
      cols: rows.map(function (r, i) {
        var d = classDef(r["class"]);
        return { label: r.name !== null ? r.name : shortAddr(r.addr), short: d.glyph,
                 group: d.label, groupShort: d.glyph, groupColor: hue[i], floor: { color: hue[i] }, cap: hue[i] };
      }),
      n: rows.length ? cols : 0, from: p ? p.from : 0, col_s: p ? p.col_s : 0,
      value: function (k, i) { return rows[i].cells ? rows[i].cells[k] : null; },
      segments: function (k, i) { return [{ f: 1, color: hue[i], alpha: step[i] }]; },
      lo: PROX_LO, hi: PROX_HI, ticks: [-100, -80, -60, -40], unit: "dBm (mean)",
      fmt: function (v) { return String(v); }, clock: H.hhmmss,
      sel: cur && cur.r < rows.length && cur.c < cols ? { k: cur.c, c: cur.r } : null,
      empty: p ? "no advertiser heard in the window" : "loading"
    });
  }

  // Hover on either isometric panel: the column under the pointer
  // named in the tooltip, as the Spectrum tab's.
  function isoTipLines(which, at) {
    var geo = which === "p" ? S.pgeo : S.geo;
    if (!geo) return null;
    var t0 = geo.from + at.k * geo.col_s, when = H.hhmmss(t0) + " to " + H.hhmmss(t0 + geo.col_s);
    if (which === "p") {
      var r = S.prows[at.c];
      if (!r) return null;
      var v = r.cells ? r.cells[at.k] : null, E = rowEdges(r);
      return [[r.name !== null ? "\"" + r.name + "\"  " + r.addr : r.addr], [when],
              [num(v) ? v.toFixed(1) + " dBm mean, " + PROX_WORD[proxBand(v, E)] + " (" + PROX_SPAN[proxBand(v, E)] + ")" : "not heard"],
              [classDef(r["class"]).label + ", P_tx " + ptxText(r.ptx, r.ptx_source), true]];
    }
    var cr = S.rows[at.c];
    if (!cr) return null;
    var hv = cr.heat && cr.heat.cells ? cr.heat.cells[at.k] : null;
    var m = cr.mix && cr.mix.cells ? cr.mix.cells[at.k] : null, top = Array.isArray(m) ? txOf(m[2]) : null;
    var out = [[classDef(cr.key).label], [when], [num(hv) ? H.fmt(hv) + " " + classUnit() : "not observed"]];
    if (top && num(m[0]) && m[0] > 0)
      out.push(["busiest " + (isAnon(top) ? "anonymous" : top.name !== null ? "\"" + top.name + "\"" : top.id) + ", " +
                H.fmt(m[3]) + " of " + H.fmt(m[0]) + " reports", true]);
    return out;
  }
  function isoHover(ev, which) {
    var cv = $(which === "p" ? "bledev-prox" : "bledev-classes"), st = which === "p" ? S.pist : S.ist;
    var at = SlothIso.at(cv, st, ev), lines = at ? isoTipLines(which, at) : null;
    st.hover = lines ? at : null;
    SlothIso.tip($("bledev-iso-tip"), lines, ev);
    SlothIso.grid(cv, st);
  }
  function isoLeave(ev, which) {
    var st = which === "p" ? S.pist : S.ist;
    if (!st.hover) return;
    st.hover = null;
    SlothIso.tip($("bledev-iso-tip"), null, ev);
    SlothIso.grid($(which === "p" ? "bledev-prox" : "bledev-classes"), st);
  }
  function isoPick(ev, which) {
    var p = which === "p", at = SlothIso.at($(p ? "bledev-prox" : "bledev-classes"), p ? S.pist : S.ist, ev);
    var key = p ? "pcur" : "cur";
    if (!at || at.c >= (p ? S.prows : S.rows).length) return;
    if (S[key] && S[key].r === at.c && S[key].c === at.k) return;
    S[key] = { r: at.c, c: at.k };
    if (p) proxGrid(); else classGrid();
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

  // The class key under each isometric panel: a swatch per class in its
  // hue, then its glyph and name; the swatches are var() references, so
  // the theme toggle repaints them by itself.
  function classKey(id) {
    var box = clear($(id));
    CLASSES.forEach(function (c) {
      var it = H.el("span", "it"), sw = H.el("span", "sw");
      sw.style.backgroundColor = classToken(c.slug);
      it.appendChild(sw);
      it.appendChild(H.el("span", "", c.glyph + " " + c.label));
      box.appendChild(it);
    });
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
    if (geo.iso) return;   // isometric: a click picks a column
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
    // Isometric, the rows run across and time recedes: left and right
    // a row, up an older cell, down a newer one.
    var MOVE = S.iso ? { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }
                     : { ArrowLeft: [0, -1], ArrowRight: [0, 1], ArrowUp: [-1, 0], ArrowDown: [1, 0] };
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
    classKey("bledev-cls-key");
    classKey("bledev-prox-key");
    load();
    if (!S.timer) S.timer = setInterval(function () { if (visible()) load(); }, REFRESH_MS);
  }

  // ── the drawer: the row's signal over the waterfall's window ─────
  var DR = { gen: 0 };
  // The S-meter (glyph.sm; owner rulings 2026-11-11: every signal
  // graphic is the meter, with its S reading, on the scale of the band
  // heard on): BLE is 2.4 GHz, so that row. The lit run is the window's
  // last sample and the two ticks its least and greatest; it was a line
  // over the window graded by the proximity band, which the waterfall
  // above and the table's dist column still say. The words it returns
  // are the canvas's label and lead the note.
  function rssiChart(pts) {
    var c = $("bledev-rssi"), sc = glyph.smDbm("2.4 GHz"), r = glyph.smRange(pts);
    var last = pts.length ? pts[pts.length - 1][1] : null;
    glyph.paint(c, glyph.sm(last, { w: c.clientWidth, h: c.clientHeight, scale: sc,
                                    lo: r ? r[0] : null, hi: r ? r[1] : null }), H.css);
    var words = last === null ? "no reading"
      : glyph.smWord(last, sc) + " " + Math.round(last) + " dBm" +
        (r[1] > r[0] ? ", the window " + glyph.smWord(r[0], sc) + " to " + glyph.smWord(r[1], sc) +
                       " (" + Math.round(r[0]) + " to " + Math.round(r[1]) + " dBm)" : "");
    c.ariaLabel = "this address's signal strength: " + words;
    return words;
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
      var words = rssiChart(pts);
      H.set("bledev-rssi-note", pts.length
        ? words + "; rf.rssi.ble, " + (r.win >= 86400 ? Math.round(r.win / 86400) + " d" : Math.round(r.win / 3600) + " h") + ", " + tier +
          " tier, n=" + pts.length + "; ticks: the window's least and greatest; 2.4 GHz scale: " + glyph.smNote()
        : "no data: no signal sample of this address in the window");
    }).catch(function (e) { if (gen === DR.gen) H.set("bledev-rssi-note", H.errText(e.message)); });
  }

  // The canvases' words, the sub text and the cursor follow the mode.
  var FLAT_LABEL = {};
  function isoMode() {
    ["bledev-classes", "bledev-prox"].forEach(function (id) {
      var c = $(id);
      if (!Object.prototype.hasOwnProperty.call(FLAT_LABEL, id)) FLAT_LABEL[id] = c.ariaLabel;
      c.ariaLabel = S.iso ? ISO_LABEL[id] : FLAT_LABEL[id];
      c.classList.toggle("iso", S.iso);
    });
    $("bledev-iso-sub").hidden = !S.iso;
    $("bledev-cls-key").hidden = $("bledev-prox-key").hidden = !S.iso || noSensor();
    if (!S.iso) { S.ist.hover = S.pist.hover = null; $("bledev-iso-tip").hidden = true; }
  }
  var ISO_LABEL = {
    "bledev-classes": "device classes by time, isometric: the classes across, the time cells receding up and to the " +
      "right with the newest in front, each column's height the class's advertisers or reports in the cell; its colour " +
      "the class's own hue (Trackers red-orange), the busiest advertisers stacked as shade steps of it, named in the key " +
      "below; arrow keys pick a cell (left and right a class, up older, down newer), the list below names it",
    "bledev-prox": "advertisers by time, isometric: the advertisers across, the time cells receding up and to the " +
      "right with the newest in front, each column's height the mean signal, taller is stronger; the advertisers " +
      "grouped by class, the class named under its span, each in its class's hue at a shade its address picks, named in " +
      "the key below; arrow keys pick a cell (left and right an advertiser, up older, down newer), the list below names it"
  };

  function init(h) {
    H = h;
    var cc = $("bledev-classes"), pc = $("bledev-prox");
    cc.tabIndex = 0;
    pc.tabIndex = 0;
    cc.addEventListener("pointermove", function (ev) {
      if (S.iso) isoHover(ev, "c");
      else if (ev.pointerType === "mouse") pick(ev, cc, S.geo, S.rows.length, "c");
    });
    cc.addEventListener("pointerdown", function (ev) { if (S.iso) isoPick(ev, "c"); else pick(ev, cc, S.geo, S.rows.length, "c"); });
    cc.addEventListener("pointerleave", function (ev) { isoLeave(ev, "c"); });
    cc.addEventListener("keydown", function (ev) { keys(ev, S.geo, S.rows.length, "c", "bledev-detail"); });
    pc.addEventListener("pointermove", function (ev) {
      if (S.iso) isoHover(ev, "p");
      else if (ev.pointerType === "mouse") pick(ev, pc, S.pgeo, S.prows.length, "p");
    });
    pc.addEventListener("pointerdown", function (ev) { if (S.iso) isoPick(ev, "p"); else pick(ev, pc, S.pgeo, S.prows.length, "p"); });
    pc.addEventListener("pointerleave", function (ev) { isoLeave(ev, "p"); });
    pc.addEventListener("click", function (ev) { labelClick(ev, pc, S.pgeo); });
    pc.addEventListener("keydown", function (ev) { keys(ev, S.pgeo, S.prows.length, "p", "bledev-pdetail"); });
    ["bledev-win", "bledev-metric", "bledev-n"].forEach(function (id) {
      $(id).addEventListener("change", function () { S.cur = S.pcur = null; load(); });
    });
    // Isometric or flat, kept per viewer (slothweb.v1.bledev.iso; the
    // default, isometric, kept as no value).
    S.iso = H.prefGet("bledev.iso") !== false;
    $("bledev-iso").checked = S.iso;
    isoMode();
    $("bledev-iso").addEventListener("change", function () {
      S.iso = $("bledev-iso").checked;
      H.prefSet("bledev.iso", S.iso ? null : false);
      isoMode();
      if (!visible()) return;
      classGrid();
      proxGrid();
    });
    window.addEventListener("resize", function () {
      if (!visible()) return;
      if (S.geo) classGrid();
      if (S.pgeo) proxGrid();
    });
  }

  window.SlothBleDev = { init: init, show: show, drawer: drawer, reset: reset };
})();
