// slothweb: the Radar view (2026-11-06, owner: "a master radar / CIC view
// of every radio heard"; docs/web-ui-spec.md §8.14, web_radar.h).
// window.SlothRadar, three hooks app.js calls:
//   SlothRadar.init(h)    once, main()'s helpers lent: el, set, getJSON
//                         (scoped), theme, tok, heat, sizeCanvas, prefGet,
//                         prefSet, show, openDrawer, openBleDrawer, scope
//   SlothRadar.show()     when the view shows: loads and keeps current
//   SlothRadar.redraw()   the canvas drawn again (a theme change)
// One half-dome centred on the sensor, Canvas 2D with a hand-written
// orthographic camera (no library can load under the page's CSP, and
// none is wanted). Every object sits at its true direction with the
// distance compressed: a GNSS satellite at its azimuth and elevation on
// the rim shell, an aircraft or APRS station at its true bearing and
// elevation angle with the slant range on a log scale (0.3 m to 300 km),
// and Wi-Fi and BLE emitters as one translucent ring per distance band
// on the ground, counted, because a single passive sensor has no
// bearing for them (web_frrs_report.c, src/position_track.h). Marks are
// shapes, not hues (R1, R10): satellite ◇, aircraft ▲, APRS ○, Wi-Fi a
// solid ring, BLE a dashed one; the one accent (--signal) is the
// selection. No gradients, shadows or fills on the chrome (R8). Every
// DOM string goes through textContent; a peer string on the canvas is
// drawn with fillText (adsb.js's precedent) and never becomes markup.
// Owner ruling 2026-11-06: the dome has no character-cell form, so it
// is exempt from R12 (the TUI's [#] sky plot is its nearest relative).
(function () {
  "use strict";
  var H = null;
  var POLL_MS = 5000, RADAR_MS = 30000, TRAIL_MS = 60000, TRAIL_H = 6;
  // The log range: 0.3 m at the centre (so the "immediate" ring is not
  // the centre point), 300 km at the rim; beyond it an object sits on
  // the rim, dimmed, with its true range in the label.
  var R_MIN = 0.3, R_MAX = 300000;
  var LOG_MIN = Math.log(R_MIN) / Math.LN10, LOG_SPAN = Math.log(R_MAX) / Math.LN10 - LOG_MIN;
  var RINGS = [1, 10, 100, 1000, 10000, 100000];
  var EARTH_M = 6371008.8, FT_M = 0.3048, ALT_SPAN_FT = 45000, CN0_SPAN = 50;
  var PITCH_MIN = 10, PITCH_MAX = 90, PITCH_DFLT = 55, ZOOM_MIN = 0.5, ZOOM_MAX = 4, ZOOM_STEP = 1.1;
  var STALE_S = 600, FIX_FRESH_S = 60, PICK_PX = 8, TAP_PX = 4, LABEL_ZOOM = 0.7;
  // src/rf_distance.h RF_BAND_*_M restated: the bands' edges, and the
  // nominal radius each ring is drawn at (far at 100 m: the band has
  // no outer edge, and the caption says so).
  var BANDS = ["immediate", "near", "room", "building", "far"];
  var BAND_EDGE = ["under 1 m", "1 to 3 m", "3 to 10 m", "10 to 30 m", "over 30 m"];
  var BAND_R = [1, 3, 10, 30, 100];
  var SPECIAL = { "7500": "unlawful interference", "7600": "radio failure", "7700": "emergency" };
  var S = { yaw: 0, pitch: PITCH_DFLT, zoom: 1, gnss: null, adsb: null, aprs: null, radar: null, trails: null,
            sel: null, selTrack: null, marks: [], rings: [], raf: 0, timer: 0, gen: 0, rgen: 0, tgen: 0,
            sgen: 0, radarAt: 0, trailAt: 0, cam: null, drag: null, errs: {}, placed: null };

  function $(id) { return document.getElementById(id); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); return n; }
  function visible() { var v = $("v-radar"); return !!v && !v.hidden; }
  function nowOf(j) { return j && num(j.now) ? j.now : Math.floor(Date.now() / 1000); }
  function age(ts, now) {
    if (!num(ts) || ts <= 0) return "-";
    var a = Math.max(0, now - ts);
    return a < 60 ? a + " s" : a < 3600 ? Math.floor(a / 60) + " min" : Math.floor(a / 3600) + " h";
  }
  function metres(m) {
    if (!num(m)) return "-";
    if (m < 10) return m.toFixed(1) + " m";
    if (m < 1000) return Math.round(m) + " m";
    if (m < 100000) return (m / 1000).toFixed(1) + " km";
    return Math.round(m / 1000) + " km";
  }
  function deg(v, dp) { return num(v) ? v.toFixed(dp) + "°" : "-"; }
  function msg(e) { return e && e.message ? e.message : "error"; }

  // ── projection: pure functions (test_radar.c pins each whole) ────
  // Log range to 0..1: 0.3 m at the centre, 300 km at the rim.
  function rn(m) {
    if (!(m > 0)) return 0;
    var f = (Math.log(m) / Math.LN10 - LOG_MIN) / LOG_SPAN;
    return f < 0 ? 0 : f > 1 ? 1 : f;
  }
  // Ground range (m, haversine on R 6371008.8) and forward azimuth
  // (deg true) from the sensor (lat0, lon0) to (lat, lon).
  function geo(lat0, lon0, lat, lon) {
    var d = Math.PI / 180, p0 = lat0 * d, p1 = lat * d, dl = (lon - lon0) * d, dp = p1 - p0;
    var a = Math.sin(dp / 2) * Math.sin(dp / 2) + Math.cos(p0) * Math.cos(p1) * Math.sin(dl / 2) * Math.sin(dl / 2);
    var range = 2 * EARTH_M * Math.atan2(Math.sqrt(a), Math.sqrt(Math.max(0, 1 - a)));
    var y = Math.sin(dl) * Math.cos(p1), x = Math.cos(p0) * Math.sin(p1) - Math.sin(p0) * Math.cos(p1) * Math.cos(dl);
    var az = Math.atan2(y, x) / d;
    return { range: range, az: (az + 360) % 360 };
  }
  // True direction, compressed distance: azimuth az and elevation el
  // (deg) with slant range m through rn(), as ENU [east, north, up] on
  // the unit dome. A satellite is the m = R_MAX case (the rim shell).
  function place(az, el, m) {
    var d = Math.PI / 180, r = rn(m), a = az * d, e = el * d;
    return [r * Math.cos(e) * Math.sin(a), r * Math.cos(e) * Math.cos(a), r * Math.sin(e)];
  }
  // The orthographic camera: yaw about up (0 north-up), pitch 10..90
  // (90 is the plan view); S the rim's half-width in px. Equal ranges
  // stay equal on screen, so picking is 2-D; depth (along the view
  // line, positive away) only dims a mark on the dome's far side.
  function project(p, cam) {
    var d = Math.PI / 180, cy = Math.cos(cam.yaw * d), sy = Math.sin(cam.yaw * d);
    var sp = Math.sin(cam.pitch * d), cp = Math.cos(cam.pitch * d);
    var xr = p[0] * cy - p[1] * sy, yr = p[0] * sy + p[1] * cy;
    return { x: cam.cx + cam.S * xr, y: cam.cy - cam.S * (yr * sp + p[2] * cp), depth: yr * cp - p[2] * sp };
  }
  // Distance in px from (x, y) to the ground ring of unit radius r:
  // its screen ellipse has half-axes S r and S r sin(pitch), whatever
  // the yaw. The polar approximation, exact on the axes.
  function ringDist(x, y, r, cam) {
    var a = cam.S * r, b = a * Math.sin(cam.pitch * Math.PI / 180);
    var dx = x - cam.cx, dy = y - cam.cy;
    if (!(a > 0) || !(b > 0)) return Math.sqrt(dx * dx + dy * dy);
    var t = Math.atan2(dy / b, dx / a);
    var ex = a * Math.cos(t), ey = b * Math.sin(t);
    return Math.sqrt((dx - ex) * (dx - ex) + (dy - ey) * (dy - ey));
  }

  // ── the painters: shapes, drawn as paths ─────────────────────────
  function diamond(g, x, y, s, fill) {
    g.beginPath();
    g.moveTo(x, y - s); g.lineTo(x + s, y); g.lineTo(x, y + s); g.lineTo(x - s, y);
    g.closePath();
    if (fill) g.fill(); else g.stroke();
  }
  function tri(g, x, y, s, heading, fill) {
    var a = (heading - 90) * Math.PI / 180, c = Math.cos(a), sn = Math.sin(a);
    g.beginPath();
    g.moveTo(x + s * c, y + s * sn);
    g.lineTo(x + s * (-0.6 * c - 0.6 * sn), y + s * (-0.6 * sn + 0.6 * c));
    g.lineTo(x + s * (-0.6 * c + 0.6 * sn), y + s * (-0.6 * sn - 0.6 * c));
    g.closePath();
    if (fill) g.fill(); else g.stroke();
  }
  function ring(g, x, y, s) {
    g.beginPath();
    g.arc(x, y, s, 0, Math.PI * 2);
    g.stroke();
  }

  // ── the sensor's position: the fix, else --location, else none ───
  function centre() {
    var j = S.gnss;
    if (!j) return null;
    var now = nowOf(j), f = j.fix, l = j.loc;
    if (f && num(f.mode) && f.mode >= 2 && num(f.lat) && num(f.lon) && num(f.ts) && now - f.ts <= FIX_FRESH_S)
      return { lat: f.lat, lon: f.lon, alt: num(f.alt_m) ? f.alt_m : null, from: "gps fix", age: now - f.ts };
    if (l && num(l.lat) && num(l.lon))
      return { lat: l.lat, lon: l.lon, alt: num(l.alt_m) ? l.alt_m : null,
               from: l["src"] === "gps" ? "last gps fix" : "--location", age: num(l.ts) ? now - l.ts : null };
    return null;
  }
  // An object at (lat, lon, altitude m above the sea) from the centre:
  // bearing, ground range, height over the sensor, elevation angle,
  // slant range, and its dome point and ground foot.
  function locate(c, lat, lon, altM) {
    var d = Math.PI / 180, gr = geo(c.lat, c.lon, lat, lon);
    var h = num(altM) ? altM - (num(c.alt) ? c.alt : 0) : 0;
    var el = Math.atan2(h, Math.max(1, gr.range)) / d;
    var slant = Math.sqrt(gr.range * gr.range + h * h);
    return { az: gr.az, range: gr.range, h: h, el: el, slant: slant,
             p: place(gr.az, el, slant), foot: place(gr.az, 0, gr.range) };
  }
  function altFt(a) { return a.on_ground ? 0 : num(a.alt_baro) ? a.alt_baro : num(a.alt_geom) ? a.alt_geom : null; }
  function emerg(a) { return a.state === "live" && a.emergency && a.emergency !== "none"; }
  function stale(ts, now) { return num(ts) && now - ts > STALE_S; }

  // ── selection ────────────────────────────────────────────────────
  function isSel(kind, key) {
    var s = S.sel;
    if (!s || s.kind !== kind) return false;
    if (kind === "sat") return s.key.gnssid === key.gnssid && s.key.prn === key.prn;
    if (kind === "ring") return s.key.fam === key.fam && s.key.band === key.band;
    return s.key === key;
  }
  function selRef() {
    var s = S.sel;
    if (!s) return null;
    if (s.kind === "sat") return ((S.gnss && S.gnss.sats) || []).filter(function (x) { return x.gnssid === s.key.gnssid && x.prn === s.key.prn; })[0] || null;
    if (s.kind === "adsb") return ((S.adsb && S.adsb.rows) || []).filter(function (x) { return x.hex === s.key; })[0] || null;
    if (s.kind === "aprs") return ((S.aprs && S.aprs.stations) || []).filter(function (x) { return x.call === s.key; })[0] || null;
    if (s.kind === "ring") {
      var fam = S.radar && S.radar[s.key.fam];
      return fam && fam.bands ? fam.bands[BANDS[s.key.band]] || null : null;
    }
    return null;
  }
  function select(kind, key) {
    S.sel = kind ? { kind: kind, key: key } : null;
    S.selTrack = null;
    if (kind === "aprs") loadSelTrack();
    panel();
    dirty();
  }

  // ── the drawing ──────────────────────────────────────────────────
  function dirty() {
    if (S.raf || !visible()) return;
    S.raf = window.requestAnimationFrame(draw);
  }
  function groundPath(g, cam, r, z) {
    var d = Math.PI / 180, sp = Math.sin(cam.pitch * d), cp = Math.cos(cam.pitch * d);
    g.beginPath();
    g.ellipse(cam.cx, cam.cy - cam.S * z * cp, Math.max(0, cam.S * r), Math.max(0, cam.S * r * sp), 0, 0, Math.PI * 2);
  }
  function polyline(g, pts) {
    if (pts.length < 2) return;
    g.beginPath();
    g.moveTo(pts[0].x, pts[0].y);
    for (var i = 1; i < pts.length; i++) g.lineTo(pts[i].x, pts[i].y);
    g.stroke();
  }
  // Label placement: right-above, else right-below, else skipped;
  // aircraft before APRS before used satellites before the rest.
  function labels(g, want, dpr) {
    var boxes = [], lh = 12 * dpr;
    want.sort(function (a, b) { return a.pri - b.pri; });
    g.textAlign = "left";
    g.textBaseline = "alphabetic";
    want.forEach(function (w) {
      var tw = g.measureText(w.text).width;
      var tries = [[w.x + 6 * dpr, w.y - 5 * dpr], [w.x + 6 * dpr, w.y + lh]];
      for (var t = 0; t < tries.length; t++) {
        var bx = { x0: tries[t][0], y0: tries[t][1] - lh, x1: tries[t][0] + tw, y1: tries[t][1] + 2 * dpr };
        var hit = false;
        for (var k = 0; k < boxes.length && !hit; k++) {
          var o = boxes[k];
          hit = bx.x0 < o.x1 && bx.x1 > o.x0 && bx.y0 < o.y1 && bx.y1 > o.y0;
        }
        if (hit) continue;
        boxes.push(bx);
        g.globalAlpha = w.alpha;
        g.fillStyle = w.color;
        g.fillText(w.text, tries[t][0], tries[t][1]);
        g.globalAlpha = 1;
        return;
      }
    });
  }
  // The dome is the page: the stage takes the window below its own top
  // edge (page offset, so a scrolled page does not grow it), at least
  // 320 px. Set before the canvas is sized from it.
  function fit() {
    var st = $("radar-stage");
    if (!st) return;
    var top = st.getBoundingClientRect().top + (window.scrollY || 0);
    var h = Math.max(320, Math.floor(window.innerHeight - top - 12)) + "px";
    if (st.style.height !== h) st.style.height = h;
  }

  function draw() {
    S.raf = 0;
    var cv = $("radar-dome");
    if (!cv || !H) return;
    fit();
    var T = H.theme(), dpr = H.sizeCanvas(cv), g = cv.getContext("2d");
    if (!g) return;
    var W = cv.width, Hh = cv.height, d = Math.PI / 180;
    g.clearRect(0, 0, W, Hh);
    var sp = Math.sin(S.pitch * d), cp = Math.cos(S.pitch * d);
    var R = Math.min(W / 2 - 14 * dpr, Hh / 2 - 14 * dpr) * S.zoom;
    var cam = { yaw: S.yaw, pitch: S.pitch, S: R, cx: W / 2, cy: Hh / 2 + R * (Math.max(sp, cp) - sp) / 2, dpr: dpr };
    S.cam = cam;
    S.marks = [];
    S.rings = [];
    var want = [], now = nowOf(S.gnss), c = centre(), zoomIn = S.zoom >= LABEL_ZOOM;
    var placed = { sats: 0, satsNo: 0, air: 0, airNo: 0, aprs: 0, aprsNo: 0 };
    g.font = Math.round(11 * dpr) + "px " + H.tok("--font-mono");
    g.lineWidth = dpr;
    g.setLineDash([]);

    // The ground: bearing spokes, the labelled range rings, the rim.
    g.strokeStyle = T.faint;
    g.fillStyle = T.muted;
    var o = project([0, 0, 0], cam);
    for (var b = 0; b < 360; b += 30) {
      var e = project(place(b, 0, R_MAX), cam);
      polyline(g, [o, e]);
    }
    g.textAlign = "center";
    g.textBaseline = "middle";
    ["N", "E", "S", "W"].forEach(function (w, i) {
      var p = project(place(i * 90, 0, R_MAX * 1.0), cam);
      var dx = p.x - cam.cx, dy = p.y - cam.cy, l = Math.sqrt(dx * dx + dy * dy) || 1;
      g.fillStyle = i === 0 ? T.ink : T.muted;
      g.fillText(w, p.x + dx / l * 9 * dpr, p.y + dy / l * 9 * dpr);
    });
    g.fillStyle = T.faint;
    g.textAlign = "left";
    RINGS.forEach(function (m) {
      var r = rn(m);
      groundPath(g, cam, r, 0);
      g.stroke();
      var p = project(place(180, 0, m), cam);
      g.fillText(metres(m), p.x + 3 * dpr, p.y - 2 * dpr);
    });
    groundPath(g, cam, 1, 0);
    g.strokeStyle = T.rule;
    g.stroke();
    // The dome: its silhouette, the 30 and 60 degree parallels, the 30
    // degree meridians.
    g.strokeStyle = T.faint;
    g.beginPath();
    g.arc(cam.cx, cam.cy, R, Math.PI, 2 * Math.PI);
    g.stroke();
    [30, 60].forEach(function (el) {
      groundPath(g, cam, Math.cos(el * d), Math.sin(el * d));
      g.stroke();
    });
    for (b = 0; b < 360; b += 30) {
      var mer = [];
      for (var el = 0; el <= 90; el += 5) mer.push(project(place(b, el, R_MAX), cam));
      polyline(g, mer);
    }

    // The Wi-Fi and BLE band rings on the ground, counted: Wi-Fi solid,
    // BLE dashed, each at the band's nominal radius, labelled with the
    // word and the count (Wi-Fi at screen right, BLE at screen left).
    var yR = -1e9, yL = -1e9;
    [["wifi", "Wi-Fi "], ["ble", "BLE "]].forEach(function (fam) {
      var cen = S.radar && S.radar[fam[0]];
      if (!cen || !cen.bands) return;
      for (var i = 0; i < BANDS.length; i++) {
        var band = cen.bands[BANDS[i]];
        if (!band || !num(band.n) || band.n <= 0) continue;
        var r = rn(BAND_R[i]), on = isSel("ring", { fam: fam[0], band: i });
        S.rings.push({ r: r, fam: fam[0], band: i, n: band.n });
        if (fam[0] === "ble") g.setLineDash([6, 4]); else g.setLineDash([]);
        g.lineWidth = on ? 2 * dpr : 1;
        g.globalAlpha = on ? 1 : 0.25;
        g.strokeStyle = on ? T.signal : T.normal;
        groundPath(g, cam, r, 0);
        g.stroke();
        g.setLineDash([]);
        g.globalAlpha = 1;
        g.fillStyle = on ? T.signal : T.muted;
        var txt = fam[1] + BANDS[i] + " " + band.n, lx, ly;
        if (fam[0] === "wifi") {
          lx = cam.cx + R * r + 4 * dpr; ly = Math.max(cam.cy, yR + 12 * dpr); yR = ly;
          g.textAlign = "left";
        } else {
          lx = cam.cx - R * r - 4 * dpr; ly = Math.max(cam.cy, yL + 12 * dpr); yL = ly;
          g.textAlign = "right";
        }
        g.fillText(txt, lx, ly);
      }
    });
    g.lineWidth = dpr;
    g.textAlign = "left";

    // The satellite trails (/api/gnss/tracks), fading toward the oldest
    // point, with gnss.js's gap rule; the selected one in the accent.
    var tr = S.trails;
    ((tr && tr.tracks) || []).forEach(function (t) {
      var pts = t.pts || [];
      if (pts.length < 2) return;
      var on = isSel("sat", { gnssid: t.gnssid, prn: t.prn });
      g.strokeStyle = on ? T.signal : T.dim;
      g.lineWidth = on ? 2 * dpr : dpr;
      for (var i = 1; i < pts.length; i++) {
        if (pts[i][0] - pts[i - 1][0] > 2 * tr.bucket_s + 60) continue;
        if (!num(pts[i][1]) || !num(pts[i][2]) || !num(pts[i - 1][1]) || !num(pts[i - 1][2])) continue;
        g.globalAlpha = 0.15 + 0.6 * i / pts.length;
        polyline(g, [project(place(pts[i - 1][2], Math.max(0, pts[i - 1][1]), R_MAX), cam),
                     project(place(pts[i][2], Math.max(0, pts[i][1]), R_MAX), cam)]);
      }
      g.globalAlpha = 1;
    });
    g.lineWidth = dpr;

    // Satellites: ◇ on the rim shell, filled when in the solution, C/N0
    // on the heat ramp over 50 dB-Hz, an unhealthy one ringed; a mark on
    // the dome's far side dimmed.
    ((S.gnss && S.gnss.sats) || []).forEach(function (s) {
      if (!num(s.el) || !num(s.az)) { placed.satsNo++; return; }
      placed.sats++;
      var p = project(place(s.az, Math.max(0, s.el), R_MAX), cam);
      var key = { gnssid: s.gnssid, prn: s.prn }, on = isSel("sat", key);
      var col = on ? T.signal : num(s.cn0) ? H.heat(s.cn0 / CN0_SPAN) : T.dim;
      var alpha = p.depth > 0.05 ? 0.55 : 1;
      if (stale(s.ts, now)) alpha = 0.35;
      g.globalAlpha = alpha;
      g.fillStyle = col; g.strokeStyle = col;
      g.lineWidth = on ? 2 * dpr : dpr;
      diamond(g, p.x, p.y, (s.used ? 5 : 4) * dpr, !!s.used);
      if (s.health === 2) { g.strokeStyle = H.tok("--heat-3"); ring(g, p.x, p.y, 8 * dpr); }
      g.globalAlpha = 1;
      S.marks.push({ x: p.x, y: p.y, kind: "sat", key: key, ref: s });
      if (zoomIn || on) want.push({ x: p.x, y: p.y, text: s.id || (String(s.gnss || "").charAt(0) + s.prn),
                                    pri: s.used ? 2 : 3, color: on ? T.signal : T.ink, alpha: alpha });
    });

    // Aircraft: ▲ rotated to the track at the true bearing and
    // elevation angle, a drop line to the ground foot, the kept track
    // through the same mapping; altitude on the heat ramp over 45,000 ft.
    ((S.adsb && S.adsb.rows) || []).forEach(function (a) {
      if (!c || !num(a.lat) || !num(a.lon)) { placed.airNo++; return; }
      placed.air++;
      var ft = altFt(a), L = locate(c, a.lat, a.lon, num(ft) ? ft * FT_M : null);
      var on = isSel("adsb", a.hex), gone = a.state === "gone" || stale(a.last_seen, now);
      var col = on ? T.signal : a.on_ground ? T.dim : H.heat(num(ft) ? Math.max(0, ft) / ALT_SPAN_FT : 0);
      var alpha = gone ? 0.35 : L.range > R_MAX ? 0.5 : 1;
      g.globalAlpha = alpha;
      g.strokeStyle = col;
      g.lineWidth = on ? 2 * dpr : dpr;
      var tp = (a.track_pts || []).filter(function (q) { return num(q[1]) && num(q[2]); }).map(function (q) {
        return project(locate(c, q[1], q[2], num(q[3]) && q[3] >= 0 ? q[3] * FT_M : 0).p, cam);
      });
      polyline(g, tp);
      var p = project(L.p, cam), f = project(L.foot, cam);
      g.strokeStyle = T.faint;
      polyline(g, [p, f]);
      g.strokeStyle = col; g.fillStyle = col;
      tri(g, p.x, p.y, 6 * dpr, num(a.track) ? a.track - S.yaw : 0, true);
      var word = emerg(a) ? a.emergency : SPECIAL[a.squawk] || "";
      if (word) { g.strokeStyle = H.tok("--heat-3"); ring(g, p.x, p.y, 10 * dpr); }
      g.globalAlpha = 1;
      S.marks.push({ x: p.x, y: p.y, kind: "adsb", key: a.hex, ref: a });
      want.push({ x: p.x, y: p.y, pri: 0, color: on ? T.signal : T.ink, alpha: alpha,
                  text: (a.flight || a.hex) + (num(ft) && !a.on_ground ? " FL" + Math.round(ft / 100) : "") +
                        (word ? " " + word : "") + (L.range > R_MAX ? " " + metres(L.range) : "") });
    });

    // APRS stations: ○ at the true bearing on the ground (or at the
    // altitude they reported), heard direct in --heat-2, else dim; the
    // selected station's kept track.
    ((S.aprs && S.aprs.stations) || []).forEach(function (a) {
      if (!c || !num(a.lat) || !num(a.lon)) { placed.aprsNo++; return; }
      placed.aprs++;
      var L = locate(c, a.lat, a.lon, num(a.alt_m) ? a.alt_m : null);
      var on = isSel("aprs", a.call), gone = a.state === "gone" || stale(a.last_seen, now);
      var col = on ? T.signal : a.heard_direct ? H.tok("--heat-2") : T.dim;
      var alpha = gone ? 0.35 : L.range > R_MAX ? 0.5 : 1;
      g.globalAlpha = alpha;
      g.lineWidth = on ? 2 * dpr : dpr;
      if (on && S.selTrack) {
        g.strokeStyle = T.signal;
        polyline(g, S.selTrack.filter(function (q) { return num(q[1]) && num(q[2]); }).map(function (q) {
          return project(locate(c, q[1], q[2], null).p, cam);
        }));
      }
      var p = project(L.p, cam);
      if (L.h !== 0) { g.strokeStyle = T.faint; polyline(g, [p, project(L.foot, cam)]); }
      g.strokeStyle = col;
      ring(g, p.x, p.y, 5 * dpr);
      g.globalAlpha = 1;
      S.marks.push({ x: p.x, y: p.y, kind: "aprs", key: a.call, ref: a });
      want.push({ x: p.x, y: p.y, pri: 1, color: on ? T.signal : T.ink, alpha: alpha,
                  text: a.call + (L.range > R_MAX ? " " + metres(L.range) : "") });
    });
    g.lineWidth = dpr;

    // The sensor itself.
    g.fillStyle = T.ink;
    g.fillRect(o.x - 2 * dpr, o.y - 2 * dpr, 4 * dpr, 4 * dpr);
    labels(g, want, dpr);
    S.placed = placed;
    H.set("radar-cam", "yaw " + Math.round(((S.yaw % 360) + 360) % 360) + "°  pitch " + Math.round(S.pitch) +
          "°  zoom " + S.zoom.toFixed(1) + "×" + (S.pitch >= PITCH_MAX ? "  (plan view)" : ""));
    caption();
  }

  // ── picking: the nearest mark within 8 px, else the nearest ring ──
  function pickAt(px, py) {
    var cam = S.cam;
    if (!cam) return null;
    var lim = PICK_PX * cam.dpr, best = null, bd = lim;
    S.marks.forEach(function (m) {
      var dx = m.x - px, dy = m.y - py, dd = Math.sqrt(dx * dx + dy * dy);
      if (dd <= bd) { bd = dd; best = { kind: m.kind, key: m.key }; }
    });
    if (best) return best;
    bd = lim;
    S.rings.forEach(function (r) {
      var dd = ringDist(px, py, r.r, cam);
      if (dd <= bd) { bd = dd; best = { kind: "ring", key: { fam: r.fam, band: r.band } }; }
    });
    return best;
  }
  function canvasPoint(ev, cv) {
    var bx = cv.getBoundingClientRect();
    return [(ev.clientX - bx.left) * (cv.width / Math.max(1, bx.width)),
            (ev.clientY - bx.top) * (cv.height / Math.max(1, bx.height))];
  }

  // ── the side panel (textContent only) ────────────────────────────
  function kvRows(kv, rows) {
    rows.forEach(function (p) {
      if (p[1] === null || p[1] === undefined) return;
      kv.appendChild(H.el("dt", "", p[0]));
      kv.appendChild(H.el("dd", "", p[1]));
    });
  }
  function openTab(label) {
    var b = $("radar-open");
    b.hidden = !label;
    b.textContent = label ? "open in " + label : "";
  }
  function panel() {
    if (!H) return;
    var side = $("radar-side"), kv = clear($("radar-side-kv")), list = clear($("radar-side-list"));
    var s = S.sel, ref = selRef(), now = nowOf(S.gnss), c = centre();
    if (!s) {
      side.hidden = true;
      openTab(null);
      return;
    }
    side.hidden = false;
    if (!ref) {
      H.set("radar-side-name", "no longer listed");
      openTab(null);
      return;
    }
    if (s.kind === "sat") {
      H.set("radar-side-name", (ref.id || ref.gnss + " PRN " + ref.prn) + (ref.veh ? " " + ref.veh.name : ""));
      kvRows(kv, [["constellation", ref.gnss + " (gnssid " + ref.gnssid + ")"], ["PRN", String(ref.prn)],
                  ["azimuth", deg(ref.az, 0) + " true"], ["elevation", deg(ref.el, 0)],
                  ["C/N0", num(ref.cn0) ? ref.cn0.toFixed(1) + " dB-Hz" : "- (not tracked)"],
                  ["used in solution", ref.used ? "yes" : "no"],
                  ["health", ref.health === 2 ? "BAD" : ref.health === 1 ? "ok" : "unknown"],
                  ["last record", age(ref.ts, now) + " ago"]]);
      openTab("GPS Sat");
    } else if (s.kind === "adsb") {
      var ft = altFt(ref), L = c && num(ref.lat) ? locate(c, ref.lat, ref.lon, num(ft) ? ft * FT_M : null) : null;
      H.set("radar-side-name", (ref.flight || ref.hex) + (ref.flight ? " (" + ref.hex + ")" : "") + (ref.state === "gone" ? ", gone" : ""));
      kvRows(kv, [["address", ref.hex + (ref.non_icao ? " (non-ICAO)" : " (ICAO 24-bit)")], ["callsign", ref.flight || "-"],
                  ["squawk", ref.squawk ? ref.squawk + (SPECIAL[ref.squawk] ? " (" + SPECIAL[ref.squawk] + ")" : "") : "-"],
                  ["emergency", ref.emergency && ref.emergency !== "none" ? ref.emergency : null],
                  ["bearing", L ? deg(L.az, 1) + " true" : "- (no sensor position)"],
                  ["ground range", L ? metres(L.range) : null],
                  ["altitude", ref.on_ground ? "on the ground" : num(ft) ? ft + " ft (" + Math.round(ft * FT_M) + " m)" : "-"],
                  ["elevation angle", L ? deg(L.el, 1) : null], ["slant range", L ? metres(L.slant) : null],
                  ["position", num(ref.lat) ? ref.lat.toFixed(5) + ", " + ref.lon.toFixed(5) : "-"],
                  ["ground speed", num(ref.gs) ? ref.gs.toFixed(0) + " kt" : null],
                  ["track", num(ref.track) ? deg(ref.track, 0) + " true" : null],
                  ["RSSI", num(ref.rssi) ? ref.rssi.toFixed(1) + " dBFS" : null],
                  ["last heard", age(ref.last_seen, now) + " ago"]]);
      openTab("ADS-B");
    } else if (s.kind === "aprs") {
      var A = c && num(ref.lat) ? locate(c, ref.lat, ref.lon, num(ref.alt_m) ? ref.alt_m : null) : null;
      H.set("radar-side-name", ref.call + (ref.state === "gone" ? ", gone" : ""));
      kvRows(kv, [["call", ref.call], ["bearing", A ? deg(A.az, 1) + " true" : "- (no sensor position)"],
                  ["ground range", A ? metres(A.range) : null],
                  ["altitude", num(ref.alt_m) ? ref.alt_m.toFixed(0) + " m (as reported)" : "- (not reported: drawn on the ground)"],
                  ["elevation angle", A ? deg(A.el, 1) : null],
                  ["position", num(ref.lat) ? ref.lat.toFixed(5) + ", " + ref.lon.toFixed(5) + " (as broadcast, unverified)" : "-"],
                  ["course", num(ref.course) ? deg(ref.course, 0) : null],
                  ["speed", num(ref.speed_kt) ? ref.speed_kt.toFixed(0) + " kt" : null],
                  ["heard via", ref.via ? (ref.direct ? "direct (" + ref.via + ")" : "digipeater " + ref.via) : "-"],
                  ["level", num(ref.level) ? String(ref.level) : null],
                  ["last heard", age(ref.last_seen, now) + " ago"]]);
      openTab("APRS");
    } else if (s.kind === "ring") {
      var ble = s.key.fam === "ble", word = BANDS[s.key.band], devs = ref.devs || [];
      var fam = S.radar[s.key.fam];
      H.set("radar-side-name", (ble ? "BLE " : "Wi-Fi ") + word);
      kvRows(kv, [["family", ble ? "BLE advertisers (the BLE receivers)" : "Wi-Fi APs and stations (the monitor radio)"],
                  ["band", word + ", " + BAND_EDGE[s.key.band] + " (sloth's estimate from signal strength, src/rf_distance.h)"],
                  ["drawn at", metres(BAND_R[s.key.band]) + (s.key.band === 4 ? " (nominal: the band has no outer edge)" : "")],
                  ["bearing", "none: a single passive sensor has no bearing for a Wi-Fi or BLE emitter"],
                  ["devices in the band", String(ref.n)],
                  ["listed", devs.length + " of " + ref.n + (devs.length < ref.n ? " (the strongest signals)" : "")],
                  ["in the family", fam.total + " rows, " + fam.estimated + " with an estimate, " + fam.none + " with a reading and none"]]);
      var ol = H.el("ol", "radar-list");
      devs.forEach(function (dv) {
        var li = H.el("li", ""), b = H.el("button", "radar-dev");
        b.type = "button";
        var id = ble ? dv.addr : dv.mac;
        b.appendChild(H.el("span", "d-bright", id));
        b.appendChild(H.el("span", "d-normal", " " + (ble ? (dv.name ? "\"" + dv.name + "\" " : "") + dv.iface
                                                              : dv.kind + (dv.ssid ? " \"" + dv.ssid + "\"" : ""))));
        b.appendChild(H.el("span", "d-dim", "  " + (num(dv.rssi) ? dv.rssi + " dBm" : "-") + "  " + age(ble ? dv.last_seen : dv.ts, now) + " ago"));
        b.addEventListener("click", function () {
          if (ble) { H.show("ble"); H.openBleDrawer(dv.addr, dv.addr_type, dv.iface); }
          else { H.show("devices"); H.openDrawer(dv.mac); }
        });
        li.appendChild(b);
        ol.appendChild(li);
      });
      list.appendChild(ol);
      openTab(ble ? "BLE Devices" : "Devices");
    }
  }
  // "open in <tab>": the family's tab, then its own selection.
  function openSel() {
    var s = S.sel, ref = selRef();
    if (!s || !ref) return;
    if (s.kind === "sat") { H.show("gnss"); if (window.SlothGnss && SlothGnss.select) SlothGnss.select(ref.gnssid, ref.prn); }
    else if (s.kind === "adsb") { H.show("adsb"); if (window.SlothAdsb && SlothAdsb.select) SlothAdsb.select(ref.hex); }
    else if (s.kind === "aprs") { H.show("aprs"); if (window.SlothAprs && SlothAprs.select) SlothAprs.select(ref.call); }
    else if (s.kind === "ring") H.show(s.key.fam === "ble" ? "ble" : "devices");
  }

  // ── the header and the caption (R9) ──────────────────────────────
  function header() {
    var h = clear($("radar-head")), c = centre(), now = nowOf(S.gnss);
    if (H.scope() === "local") {
      h.appendChild(H.el("span", "", "Local: only the host's own receiver (satellites). Aircraft, APRS, Wi-Fi monitor and BLE are the passive radios' — switch to Monitor or Hybrid"));
      return;
    }
    h.appendChild(H.el("span", "", "Radar: sensor "));
    if (c) {
      h.appendChild(H.el("b", "", c.lat.toFixed(5) + ", " + c.lon.toFixed(5)));
      h.appendChild(H.el("span", "", (num(c.alt) ? ", " + Math.round(c.alt) + " m" : "") + " (" + c.from +
                         (num(c.age) ? ", " + age(now - c.age, now) + " ago" : "") + ")"));
    } else {
      h.appendChild(H.el("b", "h2", "no sensor position: aircraft and APRS not placed"));
      h.appendChild(H.el("span", "d-dim", " (a GPS fix or --location gives one; satellites and rings are drawn)"));
    }
    var sats = (S.gnss && S.gnss.sats || []).length, air = (S.adsb && S.adsb.rows || []).length;
    var stn = (S.aprs && S.aprs.stations || []).length, rd = S.radar;
    h.appendChild(H.el("span", "", "  " + sats + " satellites, " + air + " aircraft, " + stn + " APRS" +
                       (rd && rd.wifi ? ", Wi-Fi " + rd.wifi.estimated + " in bands" : "") +
                       (rd && rd.ble ? ", BLE " + rd.ble.estimated : "")));
    var errs = Object.keys(S.errs).map(function (k) { return k + ": " + S.errs[k]; });
    if (errs.length) h.appendChild(H.el("span", "h2", "  " + errs.join("; ")));
  }
  function caption() {
    var c = centre(), now = nowOf(S.gnss), p = S.placed || {}, rd = S.radar, local = H.scope() === "local";
    var parts = ["sources /api/gnss 5 s" + (local ? "" : ", /api/adsb 5 s, /api/aprs 5 s, /api/radar 30 s") +
                 ", /api/gnss/tracks " + TRAIL_H + " h 60 s"];
    parts.push("sensor position " + (c ? c.from + (num(c.age) ? " " + age(now - c.age, now) + " ago" : "") : "none"));
    parts.push("range log 0.3 m–300 km; height is true elevation angle");
    parts.push("satellites " + (p.sats || 0) + " placed" + (p.satsNo ? ", " + p.satsNo + " without az/el" : ""));
    if (!local) {
      parts.push("aircraft " + (p.air || 0) + " placed" + (p.airNo ? ", " + p.airNo + " unplaced" : ""));
      parts.push("APRS " + (p.aprs || 0) + " placed" + (p.aprsNo ? ", " + p.aprsNo + " unplaced" : ""));
      if (rd && (rd.wifi || rd.ble)) {
        parts.push((rd.wifi ? rd.wifi.estimated : 0) + " Wi-Fi, " + (rd.ble ? rd.ble.estimated : 0) + " BLE in bands (far drawn at 100 m, nominal)");
        parts.push((rd.wifi ? rd.wifi.none : 0) + " Wi-Fi, " + (rd.ble ? rd.ble.none : 0) + " BLE without a distance estimate");
      }
      parts.push("distance from signal strength is an estimate; a ring is where the device may be, not where it is");
    } else {
      parts.push("Local: the passive radios' families are not read");
    }
    H.set("radar-cap", parts.join("; "));
  }

  // ── loading: the lent scoped getJSON for every fetch ─────────────
  function after() { header(); panel(); dirty(); caption(); }
  function loadSelTrack() {
    var s = S.sel;
    if (!s || s.kind !== "aprs" || H.scope() === "local") return;
    var my = ++S.sgen, call = s.key;
    H.getJSON("/api/aprs?call=" + encodeURIComponent(call)).then(function (j) {
      if (my !== S.sgen || j.out_of_scope || !S.sel || S.sel.key !== call) return;
      S.selTrack = j.station && Array.isArray(j.station.track_pts) ? j.station.track_pts : null;
      dirty();
    }).catch(function () { /* the mark still shows; the next poll retries */ });
  }
  function load() {
    if (!H || !visible()) return;
    var my = ++S.gen, local = H.scope() === "local";
    S.errs = {};
    H.getJSON("/api/gnss").then(function (j) {
      if (my !== S.gen) return;
      S.gnss = j;
      after();
    }).catch(function (e) { if (my === S.gen) { S.errs.gnss = msg(e); after(); } });
    if (Date.now() - S.trailAt > TRAIL_MS) {
      S.trailAt = Date.now();
      var tg = ++S.tgen;
      H.getJSON("/api/gnss/tracks?hours=" + TRAIL_H).then(function (j) {
        if (tg !== S.tgen) return;
        S.trails = j;
        dirty();
      }).catch(function () { if (tg === S.tgen) S.trails = null; });
    }
    // Under Local the passive radios' three answers are out_of_scope by
    // definition: not fetched, and the header says so.
    if (local) {
      S.adsb = S.aprs = S.radar = null;
      S.radarAt = 0;
      after();
      return;
    }
    H.getJSON("/api/adsb").then(function (j) {
      if (my !== S.gen) return;
      S.adsb = j.out_of_scope ? null : j;
      after();
    }).catch(function (e) { if (my === S.gen) { S.errs.adsb = msg(e); after(); } });
    H.getJSON("/api/aprs").then(function (j) {
      if (my !== S.gen) return;
      S.aprs = j.out_of_scope ? null : j;
      after();
    }).catch(function (e) { if (my === S.gen) { S.errs.aprs = msg(e); after(); } });
    if (Date.now() - S.radarAt > RADAR_MS) {
      S.radarAt = Date.now();
      var rg = ++S.rgen;
      H.getJSON("/api/radar").then(function (j) {
        if (rg !== S.rgen) return;
        if (j.out_of_scope) { S.radar = null; after(); return; }
        S.radar = j;
        after();
      }).catch(function (e) { if (rg === S.rgen) { S.errs.radar = msg(e); S.radarAt = 0; after(); } });
    }
    if (S.sel && S.sel.kind === "aprs") loadSelTrack();
  }

  // ── the camera's kept state: validated on read, cleared on reset ──
  function prefNum(name, lo, hi, dflt) {
    var v = H.prefGet(name);
    return typeof v === "number" && isFinite(v) && v >= lo && v <= hi ? v : dflt;
  }
  function savePrefs() {
    H.prefSet("radar.yaw", S.yaw);
    H.prefSet("radar.pitch", S.pitch);
    H.prefSet("radar.zoom", S.zoom);
  }
  function setCam(yaw, pitch, zoom) {
    S.yaw = ((yaw % 360) + 360) % 360;
    S.pitch = Math.max(PITCH_MIN, Math.min(PITCH_MAX, pitch));
    S.zoom = Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, zoom));
    savePrefs();
    dirty();
  }
  function resetCam() {
    S.yaw = 0; S.pitch = PITCH_DFLT; S.zoom = 1;
    H.prefSet("radar.yaw", null);
    H.prefSet("radar.pitch", null);
    H.prefSet("radar.zoom", null);
    dirty();
  }

  function show() {
    if (!H) return;
    load();
    dirty();
    if (!S.timer) S.timer = setInterval(function () { if (visible()) load(); }, POLL_MS);
  }

  function init(h) {
    H = h;
    S.yaw = prefNum("radar.yaw", 0, 360, 0);
    S.pitch = prefNum("radar.pitch", PITCH_MIN, PITCH_MAX, PITCH_DFLT);
    S.zoom = prefNum("radar.zoom", ZOOM_MIN, ZOOM_MAX, 1);
    var cv = $("radar-dome");
    if (!cv) return;
    cv.tabIndex = 0;
    // Pointer: a drag turns (0.5 deg/px) and tilts; a press and release
    // with under 4 px of travel picks.
    cv.addEventListener("pointerdown", function (ev) {
      if (ev.button !== 0 && ev.pointerType === "mouse") return;
      S.drag = { x: ev.clientX, y: ev.clientY, moved: 0 };
      if (cv.setPointerCapture) cv.setPointerCapture(ev.pointerId);
      cv.focus();
      ev.preventDefault();
    });
    cv.addEventListener("pointermove", function (ev) {
      var dr = S.drag;
      if (!dr) return;
      var dx = ev.clientX - dr.x, dy = ev.clientY - dr.y;
      dr.x = ev.clientX; dr.y = ev.clientY;
      dr.moved += Math.abs(dx) + Math.abs(dy);
      if (dr.moved < TAP_PX) return;
      S.yaw = (((S.yaw + dx * 0.5) % 360) + 360) % 360;
      S.pitch = Math.max(PITCH_MIN, Math.min(PITCH_MAX, S.pitch + dy * 0.5));
      dirty();
    });
    function up(ev) {
      var dr = S.drag;
      if (!dr) return;
      S.drag = null;
      if (dr.moved < TAP_PX && ev.type === "pointerup") {
        var pt = canvasPoint(ev, cv), hit = pickAt(pt[0], pt[1]);
        if (hit) select(hit.kind, hit.key); else select(null);
      } else {
        savePrefs();
      }
    }
    cv.addEventListener("pointerup", up);
    cv.addEventListener("pointercancel", up);
    cv.addEventListener("wheel", function (ev) {
      ev.preventDefault();
      setCam(S.yaw, S.pitch, ev.deltaY < 0 ? S.zoom * ZOOM_STEP : S.zoom / ZOOM_STEP);
    }, { passive: false });
    // Keys on the focused canvas: arrows turn and tilt (Shift x3), + and
    // - zoom, 0 resets, n north-up, t top-down, Escape deselects. The
    // digits are the page's view hotkeys, but that handler fires only on
    // document.body, so the canvas keeps its 0.
    cv.addEventListener("keydown", function (ev) {
      var k = ev.key, step = ev.shiftKey ? 15 : 5;
      if (k === "ArrowLeft") setCam(S.yaw - step, S.pitch, S.zoom);
      else if (k === "ArrowRight") setCam(S.yaw + step, S.pitch, S.zoom);
      else if (k === "ArrowUp") setCam(S.yaw, S.pitch + step, S.zoom);
      else if (k === "ArrowDown") setCam(S.yaw, S.pitch - step, S.zoom);
      else if (k === "+" || k === "=") setCam(S.yaw, S.pitch, S.zoom * ZOOM_STEP);
      else if (k === "-") setCam(S.yaw, S.pitch, S.zoom / ZOOM_STEP);
      else if (k === "0") resetCam();
      else if (k === "n") setCam(0, S.pitch, S.zoom);
      else if (k === "t") setCam(S.yaw, PITCH_MAX, S.zoom);
      else if (k === "Escape") select(null);
      else return;
      ev.preventDefault();
    });
    // The buttons mirror the keys, for touch.
    $("radar-reset").addEventListener("click", resetCam);
    $("radar-north").addEventListener("click", function () { setCam(0, S.pitch, S.zoom); });
    $("radar-top").addEventListener("click", function () { setCam(S.yaw, PITCH_MAX, S.zoom); });
    $("radar-zin").addEventListener("click", function () { setCam(S.yaw, S.pitch, S.zoom * ZOOM_STEP); });
    $("radar-zout").addEventListener("click", function () { setCam(S.yaw, S.pitch, S.zoom / ZOOM_STEP); });
    $("radar-side-close").addEventListener("click", function () { select(null); cv.focus(); });
    $("radar-open").addEventListener("click", openSel);
    window.addEventListener("resize", function () { if (visible()) dirty(); });
    panel();
  }

  window.SlothRadar = { init: init, show: show, redraw: dirty };
})();
