// slothweb: the Fleet view (#192 F2; docs/wiki/fleet.md, web_fleet.h).
// window.SlothFleet, two hooks app.js calls:
//   SlothFleet.init(h)    once, main()'s helpers lent: el, set, getJSON,
//                         errText, stamp, openDrawer, openBleDrawer
//   SlothFleet.show()     when the view shows: loads, and again every
//                         minute while it is shown
// Three panels: the sites on a map (SVG, an equirectangular projection
// fitted to the sites, no tiles and nothing fetched but this server's
// /api/fleet/overview), each peer's health, and the keys seen at this
// site and at a peer with each site's first-to-last-seen bar on one time
// axis (/api/fleet/shared). On the map, the emitters two or more sites
// heard, located (#192 I5, /api/fleet/locate): each candidate a
// translucent circle of its radius, the key on hover or tap, the picked
// row's range circles dashed, and a metre scale; the map fits the sites
// and the candidates, so at a 17 m baseline it is drawn in metres. Every
// peer string goes in as textContent; SVG geometry is set through the
// elements' own length properties.
(function () {
  "use strict";
  var H = null;
  var POLL_MS = 60000;
  var MAP_W = 600, MAP_H = 300, PAD = 56;
  var KINDS = ["wifi", "ble", "ap", "probe"];
  var M_DEG = 111194.9;               // metres in a degree of latitude (IUGG mean radius)
  var S = { timer: 0, gen: 0, sgen: 0, lgen: 0, ov: null, loc: null, pick: "" };

  function $(id) { return document.getElementById(id); }
  // The namespace from the page's own <svg>: the page names no URL.
  function svgEl(tag, cls) {
    var e = document.createElementNS($("fleet-map").namespaceURI, tag);
    if (cls) e.classList.add(cls);
    return e;
  }
  function svgLen(v) {
    var l = $("fleet-map").createSVGLength();
    l.value = v;
    return l;
  }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function dist(m) {
    if (!num(m)) return "-";
    if (m >= 100000) return Math.round(m / 1000).toLocaleString("en-US") + " km";
    if (m >= 1000) return (m / 1000).toFixed(1) + " km";
    return Math.round(m) + " m";
  }
  function age(s) {
    if (!num(s)) return "never";
    if (s < 120) return s + " s ago";
    if (s < 7200) return Math.round(s / 60) + " min ago";
    if (s < 172800) return Math.round(s / 3600) + " h ago";
    return Math.round(s / 86400) + " d ago";
  }
  function skew(s) {
    if (!num(s)) return "-";
    return (s > 0 ? "+" : "") + s + " s" + (Math.abs(s) >= 30 ? " (clocks disagree)" : "");
  }
  // A site's name as the page shows it: its label, else the peer's own
  // name; this site's label, else "this site".
  function siteName(name) {
    var ov = S.ov;
    if (name === "self") return ov && ov.local && ov.local.label ? ov.local.label + " (here)" : "this site";
    if (ov) for (var i = 0; i < ov.peers.length; i++)
      if (ov.peers[i].name === name) return ov.peers[i].label || name;
    return name;
  }

  // The map: each site with a position at (lon cos lat0, -lat), the box
  // fitted to the sites and to each point's radius in metres (a located
  // emitter's candidate) with a margin for the labels, one site centred.
  // The projection's ppm is pixels per metre, for the scale and radii.
  function project(pts) {
    var lat0 = 0, i;
    for (i = 0; i < pts.length; i++) lat0 += pts[i].lat / pts.length;
    var k = Math.cos(lat0 * Math.PI / 180);
    var x0 = Infinity, x1 = -Infinity, y0 = Infinity, y1 = -Infinity;
    for (i = 0; i < pts.length; i++) {
      var x = pts[i].lon * k, y = -pts[i].lat, r = (pts[i].r || 0) / M_DEG;
      x0 = Math.min(x0, x - r); x1 = Math.max(x1, x + r); y0 = Math.min(y0, y - r); y1 = Math.max(y1, y + r);
    }
    var sx = x1 - x0, sy = y1 - y0;
    var sc = Math.min(sx > 0 ? (MAP_W - 2 * PAD) / sx : Infinity, sy > 0 ? (MAP_H - 2 * PAD) / sy : Infinity);
    if (!isFinite(sc)) sc = 0;
    var cx = (x0 + x1) / 2, cy = (y0 + y1) / 2;
    var f = function (lat, lon) {
      return [MAP_W / 2 + (lon * k - cx) * sc, MAP_H / 2 + (-lat - cy) * sc];
    };
    f.ppm = sc / M_DEG;
    return f;
  }
  // A scale bar of a round length (1, 2 or 5 x 10^n m) at most 120 px,
  // at the frame's lower left.
  function scaleBar(g, ppm, sized) {
    if (!(ppm > 0)) return;
    var m = 1, steps = [1, 2, 5], best = 0;
    for (var e = -1; e < 8; e++)
      for (var j = 0; j < 3; j++) {
        m = steps[j] * Math.pow(10, e);
        if (m * ppm <= 120) best = m;
      }
    if (!best) return;
    var w = best * ppm, x = 14, y = MAP_H - 14;
    var ln = svgEl("line", "fleet-scale");
    ln.x1.baseVal.value = x; ln.y1.baseVal.value = y;
    ln.x2.baseVal.value = x + w; ln.y2.baseVal.value = y;
    g.appendChild(ln);
    var t = sized(svgEl("text", "fleet-scale-t"), 11);
    t.x.baseVal.appendItem(svgLen(x));
    t.y.baseVal.appendItem(svgLen(y - 5));
    t.textContent = best >= 1000 ? best / 1000 + " km" : best + " m";
    g.appendChild(t);
  }
  // Each located emitter's candidates, a translucent circle of its radius
  // titled with the key (hover; a tap picks the row), and the picked
  // row's range circles from each site, dashed.
  function drawLocated(g, P, at, sized) {
    var L = S.loc;
    if (!L || !L.rows) return;
    L.rows.forEach(function (r) {
      var picked = r.key === S.pick;
      r.candidates.forEach(function (c) {
        var p = P(c.lat, c.lon), e = svgEl("circle", "fleet-cand");
        if (picked) e.classList.add("picked");
        e.cx.baseVal.value = p[0]; e.cy.baseVal.value = p[1];
        e.r.baseVal.value = Math.max(3, c.radius_m * P.ppm);
        var ti = svgEl("title");
        ti.textContent = r.key + (r.label ? " " + r.label : "") + ": " + r.method.replace("_", " ") +
                         ", +/-" + c.radius_m + " m" + (r.coarse ? " (coarse)" : "");
        e.appendChild(ti);
        e.addEventListener("click", function () { pick(r.key); });
        g.appendChild(e);
      });
      if (!picked) return;
      r.sites.forEach(function (s) {
        var a = at[s.site];
        if (!a) return;
        var e = svgEl("circle", "fleet-range");
        e.cx.baseVal.value = a[0]; e.cy.baseVal.value = a[1];
        e.r.baseVal.value = s.range_m * P.ppm;
        g.appendChild(e);
      });
    });
  }
  function drawMap(ov) {
    var g = $("fleet-map-g");
    while (g.firstChild) g.removeChild(g.firstChild);
    var pts = [], none = [];
    if (num(ov.local.lat) && num(ov.local.lon)) pts.push({ name: "self", lat: ov.local.lat, lon: ov.local.lon });
    else none.push(siteName("self"));
    ov.peers.forEach(function (p) {
      if (num(p.lat) && num(p.lon)) pts.push({ name: p.name, lat: p.lat, lon: p.lon });
      else none.push(siteName(p.name));
    });
    // The fit: the sites, and each candidate with its radius (a site far
    // from the rest is left out of the fit only when emitters are drawn,
    // so the located ones are not lost in a continent's width).
    var fit = pts.slice(), far = {};
    if (S.loc && S.loc.rows && S.loc.rows.length) {
      S.loc.sites.forEach(function (s) { if (s.too_far) far[s.site] = 1; });
      fit = pts.filter(function (s) { return !far[s.name]; });
      S.loc.rows.forEach(function (r) {
        r.candidates.forEach(function (c) { fit.push({ lat: c.lat, lon: c.lon, r: c.radius_m }); });
      });
    }
    var fr = svgEl("rect", "fleet-frame");
    fr.width.baseVal.value = MAP_W - 2;
    fr.height.baseVal.value = MAP_H - 2;
    fr.x.baseVal.value = 1;
    fr.y.baseVal.value = 1;
    g.appendChild(fr);
    var at = {}, P = pts.length ? project(fit.length ? fit : pts) : null;
    // The viewBox scales with the panel: at phone width its 12 px text
    // would draw at 7, so the text is sized up by the same factor (at
    // most double), and drawn at least at 12 px on any screen.
    $("fleet-map").style.display = pts.length ? "" : "none";
    var wpx = $("fleet-map").getBoundingClientRect().width;
    var fk = wpx > 0 ? Math.min(2, Math.max(1, MAP_W / wpx)) : 1;
    function sized(t, px) { t.style.fontSize = (px * fk).toFixed(1) + "px"; return t; }
    pts.forEach(function (s) { at[s.name] = P(s.lat, s.lon); });
    if (P) drawLocated(g, P, at, sized);
    (ov.distances || []).forEach(function (d) {
      var a = at[d.a], b = at[d.b];
      if (!a || !b) return;
      var ln = svgEl("line", "fleet-line");
      ln.x1.baseVal.value = a[0]; ln.y1.baseVal.value = a[1];
      ln.x2.baseVal.value = b[0]; ln.y2.baseVal.value = b[1];
      g.appendChild(ln);
      var t = sized(svgEl("text", "fleet-dist"), 12);
      t.x.baseVal.appendItem(svgLen((a[0] + b[0]) / 2));
      t.y.baseVal.appendItem(svgLen((a[1] + b[1]) / 2 - 6 * fk));
      t.textContent = dist(d.m);
      g.appendChild(t);
    });
    pts.forEach(function (s) {
      var p = at[s.name];
      var c = svgEl("circle", "fleet-site");
      if (s.name === "self") c.classList.add("self");
      c.cx.baseVal.value = p[0]; c.cy.baseVal.value = p[1]; c.r.baseVal.value = 7;
      g.appendChild(c);
      var t = sized(svgEl("text", "fleet-name"), 13);
      t.x.baseVal.appendItem(svgLen(p[0]));
      t.y.baseVal.appendItem(svgLen(p[1] + 8 + 14 * fk));
      t.textContent = siteName(s.name);
      g.appendChild(t);
    });
    // No position at all: no frame to show (hidden above).
    if (P && pts.length > 1) scaleBar(g, P.ppm, sized);
    var note = !pts.length ? "no site has a position yet. "
             : pts.length < 2 ? "one site placed: a distance needs two positions. " : "";
    if (none.length) note += "no position for " + none.join(", ") + " (--location LAT,LON or --gps on that sensor).";
    H.set("fleet-map-note", note || "north up; positions from each sensor's --location or GPS fix, as its export last said.");
  }

  function kv(dl, k, v, warn) {
    dl.appendChild(H.el("dt", "", k));
    dl.appendChild(H.el("dd", warn ? "warn" : "", v));
  }
  function cards(ov) {
    var box = $("fleet-cards");
    while (box.firstChild) box.removeChild(box.firstChild);
    ov.peers.forEach(function (p) {
      var c = H.el("div", "fleet-card");
      c.appendChild(H.el("div", "fleet-card-h", (p.label ? p.label + " - " : "") + p.name +
                         (p.configured ? "" : " (no longer a --peer)")));
      var dl = H.el("dl");
      kv(dl, "last good pull", age(p.last_ok_age_s), !num(p.last_ok_age_s) || p.last_ok_age_s > 3 * ov.interval_s);
      kv(dl, "last attempt", age(p.last_attempt_age_s));
      if (p.last_error) kv(dl, "last refusal", p.last_error, true);
      kv(dl, "clock skew", skew(p.skew_s), num(p.skew_s) && Math.abs(p.skew_s) >= 30);
      kv(dl, "distance", dist(p.distance_m));
      var rows = [];
      KINDS.concat(["alert", "verdict"]).forEach(function (k) {
        if (p.counts && num(p.counts[k])) rows.push(k + " " + p.counts[k].toLocaleString("en-US"));
      });
      kv(dl, "rows held", rows.join(", "));
      var bf = [];
      Object.keys(p.backfill || {}).forEach(function (k) { bf.push(k); });
      kv(dl, "backfill", p.pages_refused ? "not offered: the peer's build has no paged export (F1); upgrade it"
                         : bf.length ? "fetching the rest of " + bf.join(", ") + " (" + p.pages + " pages, " +
                          p.page_failures + " refused)" : "complete" + (p.pages ? " (" + p.pages + " pages)" : ""),
         p.page_failures > 0 || !!p.pages_refused);
      kv(dl, "url", p.url || "-");
      c.appendChild(dl);
      box.appendChild(c);
    });
  }

  function loadOverview() {
    var gen = ++S.gen;
    return H.getJSON("/api/fleet/overview").then(function (ov) {
      if (gen !== S.gen) return;
      S.ov = ov;
      var empty = !ov.peers.length;
      $("fleet-empty").hidden = !empty;
      H.set("fleet-head", (ov.local.label || "this site") + ": " + ov.configured + " peer" +
            (ov.configured === 1 ? "" : "s") + " pulled every " + ov.interval_s + " s" +
            (ov.store ? "" : "; no store, nothing pulled"));
      drawMap(ov);
      cards(ov);
    }).catch(function (e) {
      if (gen === S.gen) H.set("fleet-head", H.errText(e.message));
    });
  }

  // One site's first-to-last-seen bar on the table's shared axis, named
  // short: "here", or the peer's --peer name.
  function lane(site, t0, t1) {
    var ln = H.el("div", "fleet-lane" + (site.site === "self" ? " self" : ""));
    ln.appendChild(H.el("span", "fleet-who", site.site === "self" ? "here" : site.site));
    var tr = H.el("div", "fleet-track"), b = H.el("div", "fleet-bar");
    var span = t1 > t0 ? t1 - t0 : 1;
    var a = Math.max(0, (site.first_seen - t0) / span), z = Math.min(1, (site.last_seen - t0) / span);
    b.style.left = (a * 100).toFixed(2) + "%";
    b.style.width = (Math.max(0, z - a) * 100).toFixed(2) + "%";
    b.title = H.stamp(site.first_seen) + " to " + H.stamp(site.last_seen) +
              (num(site.rssi) ? ", " + site.rssi + " dBm" : "");
    tr.appendChild(b);
    ln.appendChild(tr);
    return ln;
  }
  function devLink(kind, r) {
    var b = H.el("button", "fleet-dev", r.key);
    b.type = "button";
    b.title = "open " + r.addr;
    b.addEventListener("click", function () {
      if (kind === "ble") H.openBleDrawer(r.addr);
      else H.openDrawer(r.addr);
    });
    return b;
  }
  function loadShared() {
    var kind = $("fleet-kind").value, gen = ++S.sgen;
    if (KINDS.indexOf(kind) < 0) kind = "wifi";
    return H.getJSON("/api/fleet/shared?kind=" + kind + "&limit=100").then(function (j) {
      if (gen !== S.sgen) return;
      var box = $("fleet-shared-rows");
      while (box.firstChild) box.removeChild(box.firstChild);
      var t0 = Infinity, t1 = -Infinity;
      j.rows.forEach(function (r) {
        r.sites.forEach(function (s) {
          if (s.first_seen > 0) t0 = Math.min(t0, s.first_seen);
          t1 = Math.max(t1, s.last_seen);
        });
      });
      j.rows.forEach(function (r) {
        var row = H.el("div", "fleet-row");
        row.appendChild(devLink(kind, r));
        row.appendChild(H.el("span", "", (r.label || "") + (r.vendor ? " · " + r.vendor : "")));
        row.appendChild(H.el("span", "", r.verdict ? r.verdict.state + " (" + siteName(r.verdict.site) + ")" : "-"));
        var tl = H.el("div", "fleet-tl");
        r.sites.forEach(function (s) { tl.appendChild(lane(s, t0, t1)); });
        row.appendChild(tl);
        box.appendChild(row);
      });
      H.set("fleet-axis", j.rows.length ? "bars on one axis, " + H.stamp(t0) + " to " + H.stamp(t1) : "");
      var why = !S.ov || !S.ov.peers.length ? "no peer: nothing to compare with"
              : !j.rows.length ? "nothing of this kind seen at more than one site yet"
              : j.rows.length + " seen here and at a peer, the newest activity first";
      if (j.partial) why += "; partial: the newest " + j.scanned.toLocaleString("en-US") +
                            " peer rows were looked at, or sloth.db's read ran out of time";
      if (j.local === "none" || j.local === "unavailable") why += "; this site's sloth.db is " + j.local;
      H.set("fleet-shared-note", why);
    }).catch(function (e) {
      if (gen === S.sgen) H.set("fleet-shared-note", H.errText(e.message));
    });
  }

  // The located emitters' table: key, each site's range and band, the
  // nearer site by dB, the method, and "coarse" when the band is wider
  // than the baseline (only the side is meaningful, not the point).
  function pick(key) {
    S.pick = S.pick === key ? "" : key;
    if (S.ov) drawMap(S.ov);
    locRows();
  }
  function locRows() {
    var box = $("fleet-loc-rows"), L = S.loc;
    while (box.firstChild) box.removeChild(box.firstChild);
    if (!L) return;
    L.rows.forEach(function (r) {
      var row = H.el("div", "fleet-loc" + (r.key === S.pick ? " picked" : ""));
      var b = H.el("button", "fleet-dev", r.key);
      b.type = "button";
      b.title = "show its range circles on the map";
      b.addEventListener("click", function () { pick(r.key); });
      row.appendChild(b);
      row.appendChild(H.el("span", "", r.sites.map(function (s) {
        return (s.site === "self" ? "here" : s.site) + " " + s.range_m + " m (" + s.lo_m + "-" + s.hi_m +
               ")" + (s.calibrated ? "" : "*");
      }).join(", ")));
      // A difference inside its own sigma names no side.
      row.appendChild(H.el("span", r.nearest.within_band ? "warn" : "", r.nearest.within_band
        ? "neither (" + r.nearest.by_db + " dB, inside +/-" + r.nearest.sigma_db + ")"
        : siteName(r.nearest.site) + " by " + r.nearest.by_db + " dB (+/-" + r.nearest.sigma_db + ")"));
      row.appendChild(H.el("span", r.coarse ? "warn" : "", r.method.replace("_", " ") +
                           (r.candidates.length ? ", " + r.candidates.length + " candidate" +
                            (r.candidates.length === 1 ? "" : "s") : ", circles do not cross") +
                           (r.coarse ? "; coarse: band +/-" + r.band_m + " m over a " + r.baseline_m +
                            " m baseline" : "")));
      box.appendChild(row);
    });
  }
  function loadLocate() {
    var kind = $("fleet-kind").value, gen = ++S.lgen;
    if (kind !== "ble" && kind !== "ap") kind = "wifi";
    return H.getJSON("/api/fleet/locate?kind=" + kind + "&limit=50").then(function (j) {
      if (gen !== S.lgen) return;
      S.loc = j;
      if (S.ov) drawMap(S.ov);
      locRows();
      var cal = j.sites.map(function (s) {
        var c = s.calibration;
        return siteName(s.site) + " " + (c.state === "calibrated" ? "calibrated " + c.offset_db + " dB"
               : c.state === "refused" ? "not calibrated (" + c.offset_db + " dB, past +/-20)" : "not calibrated");
      });
      var why = !j.rows.length ? "no emitter heard at two sites within " + j.window_s + " s of each other"
              : j.rows.length + " located from signal strength (ITU-R P.1238 model, power assumed); " +
                "* an uncalibrated receiver";
      if (j.unpaired || j.stale) why += "; " + j.unpaired + " not heard close enough in time, " + j.stale + " older than " +
                                       Math.round(j.max_age_s / 60) + " min";
      if (j.partial) why += "; partial";
      H.set("fleet-loc-note", why + (cal.length ? ". Receivers: " + cal.join("; ") : ""));
    }).catch(function (e) {
      if (gen === S.lgen) H.set("fleet-loc-note", H.errText(e.message));
    });
  }

  function load() {
    loadOverview().then(loadLocate).then(loadShared);
  }
  function show() {
    load();
    if (!S.timer) S.timer = setInterval(function () { if (!$("v-fleet").hidden) load(); }, POLL_MS);
  }
  function init(h) {
    H = h;
    $("fleet-kind").addEventListener("change", function () { loadLocate(); loadShared(); });
  }
  window.SlothFleet = { init: init, show: show };
})();
