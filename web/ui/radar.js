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
// selection. No gradients, shadows or fills on the chrome (R8). With
// another sloth on the network, the fleet areas (owner request
// 2026-11-11): each emitter two or more sites heard, from
// /api/fleet/locate, as a light translucent area where it may be. Every
// DOM string goes through textContent; a peer string on the canvas is
// drawn with fillText (adsb.js's precedent) and never becomes markup.
// Owner ruling 2026-11-06: the dome has no character-cell form, so it
// is exempt from R12 (the TUI's [#] sky plot is its nearest relative).
(function () {
  "use strict";
  var H = null;
  var POLL_MS = 5000, RADAR_MS = 10000, TRAIL_MS = 60000, TRAIL_H = 6;
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
  // sloth's trend words as rf_distance.c draws them: the only motion a
  // Wi-Fi or BLE emitter has (no speed, no heading).
  var TREND_GLYPH = { approaching: "\u2198", steady: "\u2192", leaving: "\u2197" };
  // Label priorities, most important first.
  var PRI = { sel: 0, air: 1, aprs: 2, dev: 3, satUsed: 4, sat: 5, band: 6, range: 7 };
  var S = { yaw: 0, pitch: PITCH_DFLT, zoom: 1, gnss: null, adsb: null, aprs: null, radar: null, trails: null,
            sel: null, selTrack: null, marks: [], rings: [], raf: 0, timer: 0, gen: 0, rgen: 0, tgen: 0,
            sgen: 0, radarAt: 0, trailAt: 0, cam: null, drag: null, errs: {}, placed: null, labelPicks: [],
            hover: null, atrk: null, atrkAt: 0, agen: 0, atrkErr: "", aents: [],
            fleet: null, fleetAt: 0, fgen: 0, fleetOn: true, fleetErr: "", areas: [], fpeers: -1 };
  // The APRS window (owner request 2026-11-06, "a setting that defaults
  // to one hour for APRS objects"): an entity stays on the dome while its
  // newest packet of any kind is younger than this; every packet resets
  // it. The select's options, in seconds; its value is kept by app.js.
  var APRS_WINS = [900, 3600, 10800, 21600, 86400], APRS_WIN_DFLT = 3600;
  // sloth.db's APRS entities and their trails (/api/aprs/tracks), read
  // over 24 h once a minute.
  var ATRK_H = 24, ATRK_MS = 60000;
  // Device labels (owner ruling 2026-11-06): of the 50 dots a family
  // draws, only the LABEL_N most recently heard carry a label; any
  // other shows its label while hovered or selected.
  var LABEL_N = 10;
  // Fleet areas (owner request 2026-11-11: "when multiple sloths exist on
  // the network use that for better location in the radar view. just
  // make light transparent overlays for best guesses of the area the
  // signal may be coming from"): /api/fleet/locate for each kind every
  // 30 s, at most 100 rows a kind; a circle on the ground in FLEET_SEG
  // steps. The fill's alpha is FLEET_A_SUM shared out over the areas
  // drawn, at most FLEET_A_MAX: however many stack on one spot, their
  // sum stays under 1 - e^-0.4, a third of --data, so the faint device
  // rings drawn over them still read (at a sum of 1 the 133 areas of
  // 2026-11-11, all within 40 m of the centre, made it two thirds); a
  // side-only wash at FLEET_WASH of that. Fetched only with a peer
  // configured (/api/health's fleet.peers, read once), the toggle on
  // and the tab shown.
  var FLEET_KINDS = ["wifi", "ap", "ble"], FLEET_MS = 30000, FLEET_LIMIT = 100, FLEET_SEG = 72;
  var FLEET_A_MAX = 0.08, FLEET_A_SUM = 0.4, FLEET_WASH = 0.5;
  var FLEET_KIND = { wifi: "Wi-Fi station", ap: "Wi-Fi access point", ble: "BLE advertiser" };

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
  function square(g, x, y, s) {
    g.beginPath();
    g.rect(x - s, y - s, 2 * s, 2 * s);
    g.fill();
  }
  // An APRS object or item: a ✕, a shape no other family uses.
  function cross(g, x, y, s) {
    g.beginPath();
    g.moveTo(x - s, y - s); g.lineTo(x + s, y + s);
    g.moveTo(x + s, y - s); g.lineTo(x - s, y + s);
    g.stroke();
  }
  function dot(g, x, y, s) {
    g.beginPath();
    g.arc(x, y, s, 0, Math.PI * 2);
    g.fill();
  }

  // ── speed and heading: a velocity tick along the ground ──────────
  // The heading's direction on screen at an object at bearing az and
  // ground range m: its ground point and a point a small world step
  // (2 % of the range, at least 1 m) along the heading, each through
  // place() and project(), the difference normalised; null when the two
  // coincide. Through the log range, so the tick bends as the map does.
  function tickDir(az, m, hdg, cam) {
    var d = Math.PI / 180, s = Math.max(1, m * 0.02);
    var e = m * Math.sin(az * d), n = m * Math.cos(az * d);
    var e2 = e + s * Math.sin(hdg * d), n2 = n + s * Math.cos(hdg * d);
    var a = project(place(az, 0, m), cam);
    var b = project(place(Math.atan2(e2, n2) / d, 0, Math.sqrt(e2 * e2 + n2 * n2)), cam);
    var dx = b.x - a.x, dy = b.y - a.y, l = Math.sqrt(dx * dx + dy * dy);
    return l > 1e-6 ? { dx: dx / l, dy: dy / l } : null;
  }
  // The tick's length in px (before dpr) for a speed in knots.
  function tickLen(kt) {
    return Math.min(30, 6 + 14 * Math.log(1 + kt / 10) / Math.LN10);
  }
  function velTick(g, p, dir, kt, dpr) {
    var l = tickLen(kt) * dpr;
    g.beginPath();
    g.moveTo(p.x, p.y);
    g.lineTo(p.x + dir.dx * l, p.y + dir.dy * l);
    g.stroke();
  }
  function velText(kt, hdg) {
    var h = String(Math.round(hdg) % 360);
    while (h.length < 3) h = "0" + h;
    return Math.round(kt) + " kt " + h + "\u00b0";
  }

  // ── Wi-Fi and BLE devices (/api/radar devs) ──────────────────────
  // The estimate's metres, else the band's nominal radius.
  function devM(dv) {
    if (num(dv.m)) return dv.m;
    var i = BANDS.indexOf(dv.band);
    return i >= 0 ? BAND_R[i] : null;
  }
  function devKey(fam, dv) { return fam === "ble" ? dv.addr + "/" + dv.addr_type + "/" + dv.iface : dv.mac; }
  function trendGlyph(t) { return Object.prototype.hasOwnProperty.call(TREND_GLYPH, t) ? TREND_GLYPH[t] : ""; }
  // Compact: a name or SSID cut to 12, else the address's last three
  // octets; the distance and sloth's trend glyph.
  function devLabel(fam, dv) {
    var nm = fam === "ble" ? dv.name : dv.ssid, ad = String((fam === "ble" ? dv.addr : dv.mac) || "");
    var id = nm ? (nm.length > 12 ? nm.slice(0, 11) + "\u2026" : nm) : ad.slice(-8), gl = trendGlyph(dv.trend);
    return id + " ~" + metres(devM(dv)) + (gl ? " " + gl : "");
  }

  // ── fleet areas: other sloths' readings (/api/fleet/locate) ──────
  // Every shape is in east/north metres from this sensor, and reaches
  // the screen through place() and project() like every other mark: a
  // circle on the ground is not round on the log range, and is drawn as
  // FLEET_SEG points, not as an ellipse.
  function gpt(e, n) {
    return place(Math.atan2(e, n) * 180 / Math.PI, 0, Math.sqrt(e * e + n * n));
  }
  function enu(c, lat, lon) {
    var g = geo(c.lat, c.lon, lat, lon), a = g.az * Math.PI / 180;
    return { e: g.range * Math.sin(a), n: g.range * Math.cos(a) };
  }
  // Two one-sigma bands [lo, hi] about centres b metres apart share a
  // point: some r1 and r2 in them with |r1 - r2| <= b <= r1 + r2.
  function bandsMeet(lo1, hi1, lo2, hi2, b) {
    return hi1 + hi2 >= b && lo1 - hi2 <= b && lo2 - hi1 <= b;
  }
  // The areas from the three answers, one per located row, by what the
  // row honestly gives: a least-squares fix, the disc of its radius
  // ("fix"); else, when every pair of the sites' bands meet, the
  // intersection of the bands, each an annulus lo..hi about its site
  // ("bands"); else, when the nearer site is outside the difference's
  // sigma, a wash over the nearer site's half of the plane within its
  // band's outer edge ("side"); else nothing (n.none counts it).
  function fleetAreas(ans, c, n) {
    var out = [];
    (ans || []).forEach(function (j) {
      if (!j || !Array.isArray(j.sites) || !Array.isArray(j.rows)) return;
      var at = Object.create(null);
      j.sites.forEach(function (s) {
        if (s && typeof s.site === "string" && num(s.lat) && num(s.lon)) at[s.site] = enu(c, s.lat, s.lon);
      });
      j.rows.forEach(function (r) {
        if (!r || typeof r.key !== "string" || !Array.isArray(r.sites)) return;
        var ss = r.sites.filter(function (s) { return s && at[s.site] && num(s.lo_m) && num(s.hi_m) && s.hi_m > 0; });
        if (ss.length < 2) { n.none++; return; }
        var a = { id: j.kind + "|" + r.key, kind: j.kind, key: r.key, row: r, form: "", shapes: [], half: null, anchor: null };
        var cd = (Array.isArray(r.candidates) ? r.candidates : []).filter(function (q) {
          return q && num(q.lat) && num(q.lon) && num(q.radius_m) && q.radius_m > 0;
        });
        var meet = true, i, k;
        for (i = 0; i < ss.length; i++)
          for (k = 0; k < i; k++) {
            var A = at[ss[i].site], B = at[ss[k].site];
            if (!bandsMeet(ss[i].lo_m, ss[i].hi_m, ss[k].lo_m, ss[k].hi_m, Math.sqrt((A.e - B.e) * (A.e - B.e) + (A.n - B.n) * (A.n - B.n)))) meet = false;
          }
        if (r.method === "least_squares" && cd.length) {
          var p = enu(c, cd[0].lat, cd[0].lon);
          a.form = "fix";
          a.shapes.push({ e: p.e, n: p.n, lo: 0, hi: cd[0].radius_m });
          a.anchor = p;
        } else if (meet) {
          a.form = "bands";
          ss.forEach(function (s) { var q = at[s.site]; a.shapes.push({ e: q.e, n: q.n, lo: s.lo_m, hi: s.hi_m }); });
          a.anchor = cd.length ? enu(c, cd[0].lat, cd[0].lon) : bandsAnchor(a.shapes);
        } else {
          var nr = r.nearest, NA = nr && at[nr.site], NB = nr && at[nr.than];
          var mine = ss.filter(function (s) { return nr && s.site === nr.site; })[0];
          if (!NA || !NB || !mine || nr.within_band !== false || nr.site === nr.than) { n.none++; return; }
          var dx = NA.e - NB.e, dy = NA.n - NB.n, dl = Math.sqrt(dx * dx + dy * dy) || 1;
          a.form = "side";
          a.shapes.push({ e: NA.e, n: NA.n, lo: 0, hi: mine.hi_m });
          a.half = { ae: NA.e, an: NA.n, be: NB.e, bn: NB.n };
          a.anchor = { e: NA.e + dx / dl * mine.hi_m / 2, n: NA.n + dy / dl * mine.hi_m / 2 };
        }
        n[a.form]++;
        out.push(a);
      });
    });
    return out;
  }
  // The label's place for an overlap with no candidate (the range
  // circles do not cross): the point on the first site's mid-band circle
  // furthest inside every band, so the label sits on its area and not,
  // as a point along the sites' line would when one band encloses the
  // other site, outside it.
  function bandsAnchor(sh) {
    var s0 = sh[0], rm = (s0.lo + s0.hi) / 2, best = null, bv = -Infinity;
    for (var i = 0; i < FLEET_SEG; i++) {
      var t = 2 * Math.PI * i / FLEET_SEG, e = s0.e + rm * Math.sin(t), n = s0.n + rm * Math.cos(t), v = Infinity;
      // The least room left inside any other band, as a share of its width.
      for (var k = 1; k < sh.length; k++) {
        var d = Math.sqrt((e - sh[k].e) * (e - sh[k].e) + (n - sh[k].n) * (n - sh[k].n));
        v = Math.min(v, Math.min(d - sh[k].lo, sh[k].hi - d) / (sh[k].hi - sh[k].lo || 1));
      }
      if (v > bv) { bv = v; best = { e: e, n: n }; }
    }
    return best;
  }
  // A ground circle of r metres about (e, n) as one closed subpath.
  function circleTo(path, cam, e, n, r) {
    for (var i = 0; i <= FLEET_SEG; i++) {
      var t = 2 * Math.PI * i / FLEET_SEG, q = project(gpt(e + r * Math.sin(t), n + r * Math.cos(t)), cam);
      if (i) path.lineTo(q.x, q.y); else path.moveTo(q.x, q.y);
    }
    path.closePath();
  }
  // The half-plane nearer A than B, L metres each way of the bisector,
  // its four edges in FLEET_SEG steps each (a straight line on the
  // ground bends on the log range).
  function halfTo(path, cam, h, L) {
    var dx = h.ae - h.be, dy = h.an - h.bn, b = Math.sqrt(dx * dx + dy * dy) || 1, ux = dx / b, uy = dy / b;
    var mx = (h.ae + h.be) / 2, my = (h.an + h.bn) / 2;
    var cs = [[mx - uy * L, my + ux * L], [mx - uy * L + ux * L, my + ux * L + uy * L],
              [mx + uy * L + ux * L, my - ux * L + uy * L], [mx + uy * L, my - ux * L]];
    for (var k = 0; k < 4; k++) {
      var p0 = cs[k], p1 = cs[(k + 1) % 4];
      for (var i = 0; i < FLEET_SEG; i++) {
        var f = i / FLEET_SEG, q = project(gpt(p0[0] + (p1[0] - p0[0]) * f, p0[1] + (p1[1] - p0[1]) * f), cam);
        if (k || i) path.lineTo(q.x, q.y); else path.moveTo(q.x, q.y);
      }
    }
    path.closePath();
  }
  // One Path2D a shape (an annulus is its two circles under evenodd),
  // and the half-plane's: the area is where every one holds. The
  // half-plane reaches past the far edge of the nearer site's disc,
  // which is half the baseline plus its radius from the bisector: a
  // reach of twice the radius alone left no area at all once the sites
  // were more than twice the radius plus 20 m apart.
  function areaPaths(a, cam) {
    var ps = a.shapes.map(function (s) {
      var p = new Path2D();
      circleTo(p, cam, s.e, s.n, s.hi);
      if (s.lo > 0) circleTo(p, cam, s.e, s.n, s.lo);
      return p;
    });
    if (a.half) {
      var h = new Path2D();
      var hb = Math.sqrt((a.half.ae - a.half.be) * (a.half.ae - a.half.be) + (a.half.an - a.half.bn) * (a.half.an - a.half.bn));
      halfTo(h, cam, a.half, hb / 2 + a.shapes[0].hi + 10);
      ps.push(h);
    }
    return ps;
  }
  function areaHit(a, g, x, y) {
    if (!a.paths || !a.paths.length) return false;
    for (var i = 0; i < a.paths.length; i++) if (!g.isPointInPath(a.paths[i], x, y, "evenodd")) return false;
    return true;
  }
  // The link between a device's dot and its fleet area: the addresses
  // the pointer and the pick are on, of one side (fleet: an area's key;
  // else a Wi-Fi or BLE dot's address), lower case.
  function hotAddrs(fleet) {
    var out = [];
    [S.hover, S.sel].forEach(function (s) {
      if (!s) return;
      if (fleet && s.kind === "fleet") out.push(s.key.slice(s.key.indexOf("|") + 1).toLowerCase());
      if (!fleet && (s.kind === "wifi" || s.kind === "ble")) out.push(String(s.key).split("/")[0].toLowerCase());
    });
    return out;
  }
  // A row names this site "self" (web_locate.c); the page says so.
  function siteWord(n) { return n === "self" ? "this site" : String(n); }
  function areaLabel(a) {
    var r = a.row, id = r.label || r.key;
    id = id.length > 17 ? id.slice(0, 16) + "\u2026" : id;
    return id + " \u00b7 " + (a.form === "fix" ? "may be within " + metres(a.shapes[0].hi)
                             : a.form === "bands" ? "bands of " + a.shapes.length + " sites"
                             : "nearer " + siteWord(r.nearest.site)) +
           (num(r.band_m) ? ", band \u00b1" + metres(r.band_m) : "") + (r.coarse ? ", coarse" : "");
  }
  // Any answer naming a site other than this one: the toggle's reason
  // to exist.
  function fleetPeers() {
    return !!S.fleet && S.fleet.some(function (j) {
      return !!j && Array.isArray(j.sites) && j.sites.some(function (s) { return s && s.site !== "self"; });
    });
  }
  // Worth asking: a peer configured, the toggle on, not Local.
  function fleetWanted() { return S.fpeers > 0 && S.fleetOn && H.scope() !== "local"; }
  function fleetBtn() {
    var b = $("radar-fleet");
    if (!b) return;
    b.hidden = !(S.fpeers > 0) || H.scope() === "local";
    b.textContent = S.fleetOn ? "fleet areas on" : "fleet areas off";
  }
  // Drawn under every mark, after the ground and the dome: each area
  // its clip of every path filled once in --data at the shared alpha,
  // so overlaps read darker; the hovered or picked one, or one whose
  // device dot is, outlined. Then the other sites, a hollow □ and the
  // name.
  function drawFleet(g, cam, c, T, W, Hh, dpr, want, placed) {
    S.areas = [];
    var n = { fix: 0, bands: 0, side: 0, none: 0 };
    placed.fleet = n;
    if (!S.fleetOn || !c || !fleetPeers()) return;
    var areas = fleetAreas(S.fleet, c, n), al = Math.min(FLEET_A_MAX, FLEET_A_SUM / Math.max(1, areas.length));
    var dhot = hotAddrs(false);
    areas.forEach(function (a) {
      var ps = areaPaths(a, cam), on = isSel("fleet", a.id);
      var hov = !!S.hover && S.hover.kind === "fleet" && S.hover.key === a.id;
      var lk = dhot.indexOf(a.key.toLowerCase()) >= 0;
      a.paths = ps;
      g.save();
      ps.forEach(function (p) { g.clip(p, "evenodd"); });
      g.globalAlpha = (a.form === "side" ? FLEET_WASH : 1) * (on || hov || lk ? Math.max(0.2, al) : al);
      g.fillStyle = on ? T.signal : T.data;
      g.fillRect(0, 0, W, Hh);
      g.restore();
      if (on || hov || lk) {
        g.globalAlpha = 0.6;
        g.strokeStyle = on ? T.signal : T.ink;
        g.lineWidth = dpr;
        ps.forEach(function (p) { g.stroke(p); });
        g.globalAlpha = 1;
        var q = project(gpt(a.anchor.e, a.anchor.n), cam);
        want.push({ x: q.x, y: q.y, text: areaLabel(a), pri: PRI.sel, color: on ? T.signal : T.ink, alpha: 1 });
      }
      S.areas.push(a);
    });
    var seen = Object.create(null);
    g.strokeStyle = T.muted;
    g.lineWidth = dpr;
    S.fleet.forEach(function (j) {
      ((j && j.sites) || []).forEach(function (s) {
        if (!s || s.site === "self" || seen[s.site] || !num(s.lat) || !num(s.lon)) return;
        seen[s.site] = 1;
        var q = enu(c, s.lat, s.lon), p = project(gpt(q.e, q.n), cam);
        g.strokeRect(p.x - 3 * dpr, p.y - 3 * dpr, 6 * dpr, 6 * dpr);
        want.push({ x: p.x, y: p.y, text: s.site, pri: PRI.aprs, color: T.muted, alpha: 1 });
      });
    });
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
    if (s.kind === "aprs") return S.aents.filter(function (x) { return x.id === s.key; })[0] || null;
    if (s.kind === "ble" || s.kind === "wifi") {
      var list = (S.radar && S.radar.devs && S.radar.devs[s.kind]) || [];
      return list.filter(function (x) { return devKey(s.kind, x) === s.key; })[0] || null;
    }
    if (s.kind === "ring") {
      var fam = S.radar && S.radar[s.key.fam];
      return fam && fam.bands ? fam.bands[BANDS[s.key.band]] || null : null;
    }
    if (s.kind === "fleet") return S.areas.filter(function (a) { return a.id === s.key; })[0] || null;
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
  // ── APRS entities: stations, objects and items (sloth.db + live) ─
  function aprsWin() {
    var el = $("radar-aprs-win"), v = el ? Number(el.value) : NaN;
    return APRS_WINS.indexOf(v) >= 0 ? v : APRS_WIN_DFLT;
  }
  function winText(s) { return s < 3600 ? Math.round(s / 60) + " min" : Math.round(s / 3600) + " h"; }
  // sloth.db's entities (/api/aprs/tracks: stations by source call,
  // objects and items by their own name, each with its newest packet's
  // time, its newest position, status, comment and a moving one's 24 h
  // trail) merged with the live table's stations (/api/aprs), keyed by
  // kind and key: the live row wins for the latest position, the newer
  // last_seen of the two counts. Then the window: an entity is shown
  // while now - last_seen <= win, last_seen being its newest packet of
  // any kind, so a status-only packet keeps it (at its last position).
  function aprsEntities(now, win) {
    var by = Object.create(null), out = [];
    function get(kind, key) {
      var id = kind + "|" + key;
      if (!by[id]) {
        by[id] = { id: id, kind: kind, key: key, via: "", symbol: "", last_seen: 0, moving: false,
                   status: "", comment: "", pts: [], bucket_s: 0, live: null };
        out.push(by[id]);
      }
      return by[id];
    }
    var t = S.atrk, cols = t && Array.isArray(t.cols) ? t.cols : [];
    ((t && t.entities) || []).forEach(function (r) {
      if (!Array.isArray(r)) return;
      var o = {};
      cols.forEach(function (c, i) { o[c] = r[i]; });
      if (typeof o.key !== "string" || !o.key) return;
      var e = get(o.object ? "object" : "station", o.key);
      e.via = typeof o.via === "string" ? o.via : "";
      e.symbol = typeof o.symbol === "string" ? o.symbol : "";
      e.last_seen = num(o.last_seen) ? o.last_seen : 0;
      e.lat = o.lat; e.lon = o.lon; e.alt_m = o.alt_m; e.speed_kt = o.speed_kt; e.course = o.course;
      e.moving = !!o.moving;
      e.status = typeof o.status === "string" ? o.status : "";
      e.comment = typeof o.comment === "string" ? o.comment : "";
      e.pts = Array.isArray(o.pts) ? o.pts : [];
      e.bucket_s = num(t.bucket_s) ? t.bucket_s : 1800;
    });
    ((S.aprs && S.aprs.stations) || []).forEach(function (a) {
      if (typeof a.call !== "string" || !a.call) return;
      var e = get("station", a.call);
      e.live = a;
      if (num(a.lat) && num(a.lon)) {
        e.lat = a.lat; e.lon = a.lon; e.alt_m = a.alt_m; e.speed_kt = a.speed_kt; e.course = a.course;
      }
      if (num(a.last_seen) && a.last_seen > e.last_seen) e.last_seen = a.last_seen;
      if (a.status) e.status = a.status;
      if (a.comment) e.comment = a.comment;
      if (!e.symbol && typeof a.symbol === "string") e.symbol = a.symbol;
    });
    return out.filter(function (e) { return now - e.last_seen <= win; });
  }
  // A moving entity's trail on the ground through the same mapping,
  // fading toward its oldest point (alpha 0.15 to 0.6 by age), broken
  // across a gap of more than two buckets.
  function trail(g, pts, bucket, c, cam, col, dpr) {
    if (!Array.isArray(pts) || pts.length < 2) return;
    var t0 = pts[0][0], span = Math.max(1, pts[pts.length - 1][0] - t0), prev = null;
    g.strokeStyle = col;
    g.lineWidth = dpr;
    for (var i = 0; i < pts.length; i++) {
      var q = pts[i];
      if (!Array.isArray(q) || !num(q[0]) || !num(q[1]) || !num(q[2])) { prev = null; continue; }
      var pt = project(locate(c, q[1], q[2], null).p, cam);
      if (prev && q[0] - prev.ts <= 2 * bucket) {
        g.globalAlpha = 0.15 + 0.45 * (q[0] - t0) / span;
        polyline(g, [prev.p, pt]);
      }
      prev = { p: pt, ts: q[0] };
    }
    g.globalAlpha = 1;
  }
  // The label: the call, or an object's name and who reported it; its
  // speed and heading; with room, its status (else comment) cut to 16.
  function aprsLabel(e, mv, far) {
    var base = (e.kind === "object" ? e.key + " (obj via " + (e.via || "?") + ")" : e.key) +
               (mv ? " " + velText(e.speed_kt, e.course) : "") + (far ? " " + far : "");
    var note = e.status || e.comment;
    if (!note) return { text: base, alt: null };
    return { text: base + " \u00b7 " + (note.length > 16 ? note.slice(0, 15) + "\u2026" : note), alt: base };
  }

  // ── label layout: one pass a frame; no label ever on another ─────
  // Every label is a request {x, y (its anchor), text, pri, color,
  // alpha, and col "R"|"L" (a north-axis device), left (prefers the
  // anchor's left), fixed (N E S W), pick (a device, clickable)}.
  // drawLabels() measures them all and places them in this order: the
  // fixed ones; the selected, aircraft and APRS greedily; the devices in
  // two stacked columns with leaders (Wi-Fi right, BLE left); the rest
  // greedily. put() is the one way a label reaches the canvas, and it
  // refuses a box off the canvas or touching one already placed, so the
  // invariant holds whatever a placer proposes; a label with no room is
  // skipped, its mark still drawn.
  function boxHit(b, boxes) {
    for (var k = 0; k < boxes.length; k++) {
      var o = boxes[k];
      if (b.x0 < o.x1 && b.x1 > o.x0 && b.y0 < o.y1 && b.y1 > o.y0) return true;
    }
    return false;
  }
  // One-dimensional stacking: anchors ys ascending (a label's wanted
  // bottom edge); each bottom at least its anchor, top and a step below
  // the previous one; when the last passes bottom, the column relaxes
  // upward from it.
  function stackColumn(ys, h, gap, top, bottom) {
    var out = [], n = ys.length, step = h + gap, i;
    for (i = 0; i < n; i++) out.push(Math.max(ys[i], top, i ? out[i - 1] + step : top));
    if (n && out[n - 1] > bottom) {
      out[n - 1] = bottom;
      for (i = n - 2; i >= 0; i--) out[i] = Math.min(out[i], out[i + 1] - step);
    }
    return out;
  }
  // The candidate boxes (w by h) around an anchor at radius r: eight
  // directions, right of it first (left first for a left label).
  function candidates(x, y, w, h, r, left) {
    var D = left ? [[-1, -1], [-1, 1], [-1, 0], [1, -1], [1, 1], [1, 0], [0, -1], [0, 1]]
                 : [[1, -1], [1, 1], [1, 0], [-1, -1], [-1, 1], [-1, 0], [0, -1], [0, 1]];
    return D.map(function (d) {
      var x0 = d[0] > 0 ? x + r : d[0] < 0 ? x - r - w : x - w / 2;
      var y0 = d[1] > 0 ? y + r : d[1] < 0 ? y - r - h : y - h / 2;
      return { x0: x0, y0: y0, x1: x0 + w, y1: y0 + h };
    });
  }
  // The panels floating over the dome (header, picked panel, caption),
  // in canvas pixels: no label is placed under one.
  function overlayBoxes(cv) {
    var cb = cv.getBoundingClientRect(), sx = cv.width / Math.max(1, cb.width), sy = cv.height / Math.max(1, cb.height);
    var out = [], ov = document.querySelectorAll("#radar-stage .radar-ov");
    for (var i = 0; i < ov.length; i++) {
      if (ov[i].hidden || !ov[i].offsetParent) continue;
      var r = ov[i].getBoundingClientRect();
      out.push({ x0: (r.left - cb.left) * sx, y0: (r.top - cb.top) * sy, x1: (r.right - cb.left) * sx, y1: (r.bottom - cb.top) * sy });
    }
    return out;
  }
  function drawLabels(g, want, dpr, W, Hh, T, blocked) {
    var boxes = (blocked || []).slice(), h = 12 * dpr, gap = 2 * dpr;
    g.textAlign = "left";
    g.textBaseline = "top";
    want.forEach(function (w) { w.w = g.measureText(w.text).width; });
    want.sort(function (a, b) { return a.pri - b.pri; });
    function put(w, b, lead) {
      if (b.x0 < 0 || b.y0 < 0 || b.x1 > W || b.y1 > Hh || boxHit(b, boxes)) return false;
      boxes.push(b);
      g.globalAlpha = w.alpha;
      if (lead) {
        g.strokeStyle = T.rule;
        g.lineWidth = dpr;
        g.setLineDash([]);
        polyline(g, [{ x: w.x, y: w.y }, { x: w.x < b.x0 ? b.x0 : w.x > b.x1 ? b.x1 : (b.x0 + b.x1) / 2, y: (b.y0 + b.y1) / 2 }]);
      }
      g.fillStyle = w.color;
      g.fillText(w.text, b.x0, b.y0 + dpr);
      g.globalAlpha = 1;
      if (w.pick) S.labelPicks.push({ box: b, pick: w.pick });
      return true;
    }
    function greedy(w) {
      var radii = [6 * dpr, 16 * dpr], cs, i, k;
      for (i = 0; i < radii.length; i++) {
        cs = candidates(w.x, w.y, w.w, h, radii[i], w.left);
        for (k = 0; k < cs.length; k++) if (put(w, cs[k], false)) return;
      }
      // No room for the long form: the short one, from the start.
      if (w.alt) {
        w.text = w.alt;
        w.alt = null;
        w.w = g.measureText(w.text).width;
        greedy(w);
        return;
      }
      if (w.pri > PRI.aprs) return;
      cs = candidates(w.x, w.y, w.w, h, 30 * dpr, w.left);
      for (k = 0; k < cs.length; k++) if (put(w, cs[k], true)) return;
    }
    function column(items, right) {
      if (!items.length) return;
      items.sort(function (a, b) { return a.y - b.y; });
      var xs = items.map(function (w) { return w.x; }), ws = items.map(function (w) { return w.w; });
      var maxw = Math.max.apply(null, ws);
      var cx = right ? Math.min(Math.max.apply(null, xs) + 10 * dpr, W - maxw - 2 * dpr)
                     : Math.max(Math.min.apply(null, xs) - 10 * dpr, maxw + 2 * dpr);
      var ys = stackColumn(items.map(function (w) { return w.y + h / 2; }), h, gap, h, Hh);
      items.forEach(function (w, i) {
        put(w, { x0: right ? cx : cx - w.w, x1: right ? cx + w.w : cx, y0: ys[i] - h, y1: ys[i] }, true);
      });
    }
    want.filter(function (w) { return w.fixed; }).forEach(function (w) {
      put(w, { x0: w.x - w.w / 2, y0: w.y - h / 2, x1: w.x + w.w / 2, y1: w.y + h / 2 }, false);
    });
    want.filter(function (w) { return !w.fixed && !w.col && w.pri <= PRI.aprs; }).forEach(greedy);
    column(want.filter(function (w) { return w.col === "R"; }), true);
    column(want.filter(function (w) { return w.col === "L"; }), false);
    want.filter(function (w) { return !w.fixed && !w.col && w.pri > PRI.aprs; }).forEach(greedy);
  }
  // The dome is the page: the stage takes the window below its own top
  // edge (page offset, so a scrolled page does not grow it), at least
  // 320 px. Set before the canvas is sized from it.
  function fit() {
    var st = $("radar-stage");
    if (!st || full()) return;
    var top = st.getBoundingClientRect().top + (window.scrollY || 0);
    var h = Math.max(320, Math.floor(window.innerHeight - top - 12)) + "px";
    if (st.style.height !== h) st.style.height = h;
  }

  // Full screen (owner request, 2026-11-06: "only the dome visible"):
  // the stage alone goes full screen through the Fullscreen API, and
  // radar.css hides every panel over it there. Esc (the browser's own)
  // or f on the focused dome leaves. Hidden where the API is not.
  function full() { return document.fullscreenElement === $("radar-stage"); }
  function toggleFull() {
    var st = $("radar-stage");
    if (!st || !document.fullscreenEnabled) return;
    if (full()) document.exitFullscreen();
    else st.requestFullscreen().then(function () { $("radar-dome").focus(); }, function () {});
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
    S.labelPicks = [];
    var want = [], now = nowOf(S.gnss), c = centre(), zoomIn = S.zoom >= LABEL_ZOOM;
    var placed = { sats: 0, satsNo: 0, air: 0, airNo: 0, aprs: 0, aprsNo: 0, aprsN: 0, aprsMoving: 0, aprsObj: 0 };
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
    ["N", "E", "S", "W"].forEach(function (w, i) {
      var p = project(place(i * 90, 0, R_MAX * 1.0), cam);
      var dx = p.x - cam.cx, dy = p.y - cam.cy, l = Math.sqrt(dx * dx + dy * dy) || 1;
      want.push({ fixed: true, x: p.x + dx / l * 9 * dpr, y: p.y + dy / l * 9 * dpr, text: w, pri: -1,
                  color: i === 0 ? T.ink : T.muted, alpha: 1 });
    });
    RINGS.forEach(function (m) {
      var r = rn(m);
      groundPath(g, cam, r, 0);
      g.stroke();
      var p = project(place(180, 0, m), cam);
      want.push({ x: p.x, y: p.y, text: metres(m), pri: PRI.range, color: T.faint, alpha: 1 });
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
    drawFleet(g, cam, c, T, W, Hh, dpr, want, placed);
    g.globalAlpha = 1;

    // The Wi-Fi and BLE band rings on the ground, counted: Wi-Fi solid,
    // BLE dashed, each at the band's nominal radius, faint (the devices
    // carry their own rings), labelled with the word and the count
    // (Wi-Fi at the ring's screen right, BLE at its left).
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
        g.globalAlpha = on ? 1 : 0.09;
        g.strokeStyle = on ? T.signal : T.normal;
        groundPath(g, cam, r, 0);
        g.stroke();
        g.setLineDash([]);
        g.globalAlpha = 1;
        var txt = fam[1] + BANDS[i] + " " + band.n, ble = fam[0] === "ble";
        want.push({ x: cam.cx + (ble ? -1 : 1) * R * r, y: cam.cy, text: txt, left: ble,
                    pri: on ? PRI.sel : PRI.band, color: on ? T.signal : T.muted, alpha: 1 });
      }
    });
    g.lineWidth = dpr;

    // Wi-Fi and BLE devices on the north axis: a single passive sensor
    // has no bearing for them, so each of the 50 most recently heard of
    // each family sits at azimuth 0 on the ground at its own estimated
    // distance (the band's nominal radius when the record carried no
    // metres): ■ Wi-Fi, ● BLE, each with its own faint ring (Wi-Fi
    // solid, BLE dashed); their labels stack in two columns.
    var shown = { ble: 0, wifi: 0 }, fhot = hotAddrs(true);
    [["wifi", "R"], ["ble", "L"]].forEach(function (fam) {
      var list = (S.radar && S.radar.devs && S.radar.devs[fam[0]]) || [];
      list.forEach(function (dv, idx) {
        var m = devM(dv);
        if (!num(m)) return;
        shown[fam[0]]++;
        var key = devKey(fam[0], dv), on = isSel(fam[0], key), ble = fam[0] === "ble";
        var hov = !!S.hover && S.hover.kind === fam[0] && S.hover.key === key;
        var old = stale(ble ? dv.last_seen : dv.ts, now), col = on ? T.signal : T.normal;
        if (ble) g.setLineDash([6, 4]); else g.setLineDash([]);
        g.lineWidth = 1;
        g.globalAlpha = on ? 0.6 : old ? 0.06 : 0.15;
        g.strokeStyle = col;
        groundPath(g, cam, rn(m), 0);
        g.stroke();
        g.setLineDash([]);
        var p = project(place(0, 0, m), cam);
        g.globalAlpha = old ? 0.35 : 1;
        g.fillStyle = col;
        if (ble) dot(g, p.x, p.y, 3 * dpr); else square(g, p.x, p.y, 3 * dpr);
        g.globalAlpha = 1;
        if (fhot.indexOf(String(ble ? dv.addr : dv.mac).toLowerCase()) >= 0) { g.strokeStyle = T.ink; ring(g, p.x, p.y, 6 * dpr); }
        S.marks.push({ x: p.x, y: p.y, kind: fam[0], key: key, ref: dv });
        if (idx < LABEL_N || on || hov)
          want.push({ x: p.x, y: p.y, col: fam[1], text: devLabel(fam[0], dv), pri: on || hov ? PRI.sel : PRI.dev,
                      color: on ? T.signal : hov ? T.ink : T.muted, alpha: old && !hov ? 0.35 : 1,
                      pick: { kind: fam[0], key: key } });
      });
    });
    g.lineWidth = dpr;

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
                                    pri: on ? PRI.sel : s.used ? PRI.satUsed : PRI.sat, color: on ? T.signal : T.ink, alpha: alpha });
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
      var mv = num(a.gs) && a.gs > 0 && num(a.track);
      var dir = num(a.track) ? tickDir(L.az, L.range, a.track, cam) : null;
      tri(g, p.x, p.y, 6 * dpr, dir ? Math.atan2(dir.dy, dir.dx) / d + 90 : 0, true);
      if (mv && dir) velTick(g, p, dir, a.gs, dpr);
      var word = emerg(a) ? a.emergency : SPECIAL[a.squawk] || "";
      if (word) { g.strokeStyle = H.tok("--heat-3"); ring(g, p.x, p.y, 10 * dpr); }
      g.globalAlpha = 1;
      S.marks.push({ x: p.x, y: p.y, kind: "adsb", key: a.hex, ref: a });
      want.push({ x: p.x, y: p.y, pri: on ? PRI.sel : PRI.air, color: on ? T.signal : T.ink, alpha: alpha,
                  text: (a.flight || a.hex) + (num(ft) && !a.on_ground ? " FL" + Math.round(ft / 100) : "") +
                        (mv ? " " + velText(a.gs, a.track) : "") +
                        (word ? " " + word : "") + (L.range > R_MAX ? " " + metres(L.range) : "") });
    });

    // APRS stations (○) and objects (✕) heard within the window, at the
    // true bearing on the ground (or the altitude they reported); a
    // station heard direct in --heat-2, else dim; a moving one's 24 h
    // trail, else the selected station's live track.
    var awin = aprsWin(), ents = aprsEntities(now, awin);
    S.aents = ents;
    ents.forEach(function (e) {
      placed.aprsN++;
      if (e.moving) placed.aprsMoving++;
      if (e.kind === "object") placed.aprsObj++;
      if (!c || !num(e.lat) || !num(e.lon)) { placed.aprsNo++; return; }
      placed.aprs++;
      var a = e.live, L = locate(c, e.lat, e.lon, num(e.alt_m) ? e.alt_m : null);
      var on = isSel("aprs", e.id), gone = (a && a.state === "gone") || stale(e.last_seen, now);
      var col = on ? T.signal : e.kind === "object" ? T.normal : a && a.heard_direct ? H.tok("--heat-2") : T.dim;
      var alpha = gone ? 0.35 : L.range > R_MAX ? 0.5 : 1;
      if (e.moving) trail(g, e.pts, e.bucket_s, c, cam, on ? T.signal : T.muted, dpr);
      g.globalAlpha = alpha;
      g.lineWidth = on ? 2 * dpr : dpr;
      if (on && !e.moving && S.selTrack) {
        g.strokeStyle = T.signal;
        polyline(g, S.selTrack.filter(function (q) { return num(q[1]) && num(q[2]); }).map(function (q) {
          return project(locate(c, q[1], q[2], null).p, cam);
        }));
      }
      var p = project(L.p, cam);
      if (L.h !== 0) { g.strokeStyle = T.faint; polyline(g, [p, project(L.foot, cam)]); }
      g.strokeStyle = col;
      if (e.kind === "object") cross(g, p.x, p.y, 4 * dpr); else ring(g, p.x, p.y, 5 * dpr);
      var mv = num(e.speed_kt) && e.speed_kt > 0 && num(e.course);
      var dir = mv ? tickDir(L.az, L.range, e.course, cam) : null;
      if (dir) velTick(g, p, dir, e.speed_kt, dpr);
      g.globalAlpha = 1;
      S.marks.push({ x: p.x, y: p.y, kind: "aprs", key: e.id, ref: e });
      var lb = aprsLabel(e, mv, L.range > R_MAX ? metres(L.range) : "");
      want.push({ x: p.x, y: p.y, pri: on ? PRI.sel : PRI.aprs, color: on ? T.signal : T.ink, alpha: alpha,
                  text: lb.text, alt: lb.alt });
    });
    g.lineWidth = dpr;

    // The sensor itself.
    g.fillStyle = T.ink;
    g.fillRect(o.x - 2 * dpr, o.y - 2 * dpr, 4 * dpr, 4 * dpr);
    drawLabels(g, want, dpr, W, Hh, T, overlayBoxes(cv));
    placed.ble = shown.ble;
    placed.wifi = shown.wifi;
    S.placed = placed;
    H.set("radar-cam", "yaw " + Math.round(((S.yaw % 360) + 360) % 360) + "°  pitch " + Math.round(S.pitch) +
          "°  zoom " + S.zoom.toFixed(1) + "×" + (S.pitch >= PITCH_MAX ? "  (plan view)" : ""));
    caption();
  }

  // ── picking: the nearest mark within 8 px, else the nearest ring ──
  function pickAt(px, py, areas) {
    var cam = S.cam;
    if (!cam) return null;
    var lim = PICK_PX * cam.dpr, best = null, bd = lim;
    // A device's stacked label is its handle where dots crowd the axis.
    for (var i = 0; i < S.labelPicks.length; i++) {
      var b = S.labelPicks[i].box;
      if (px >= b.x0 && px <= b.x1 && py >= b.y0 && py <= b.y1) return S.labelPicks[i].pick;
    }
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
    if (best || !areas) return best;
    // A fleet area last, the one drawn on top first: it is wide, and only
    // when the caller asks (hover always; a tap only with nothing picked,
    // so a tap off every mark still clears the panel where the areas
    // cover the centre).
    var g = $("radar-dome").getContext("2d");
    for (i = S.areas.length - 1; g && i >= 0; i--) if (areaHit(S.areas[i], g, px, py)) return { kind: "fleet", key: S.areas[i].id };
    return null;
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
      var lv = ref.live || {}, obj = ref.kind === "object", np = (ref.pts || []).length;
      var A = c && num(ref.lat) ? locate(c, ref.lat, ref.lon, num(ref.alt_m) ? ref.alt_m : null) : null;
      var span = np > 1 ? ref.pts[np - 1][0] - ref.pts[0][0] : 0;
      H.set("radar-side-name", ref.key + (obj ? " (object)" : "") + (lv.state === "gone" ? ", gone" : ""));
      kvRows(kv, [[obj ? "object" : "call", obj ? ref.key + ", object, reported by " + (ref.via || "-") : ref.key],
                  ["bearing", A ? deg(A.az, 1) + " true" : "- (no sensor position)"],
                  ["ground range", A ? metres(A.range) : null],
                  ["altitude", num(ref.alt_m) ? ref.alt_m.toFixed(0) + " m (as reported)" : "- (not reported: drawn on the ground)"],
                  ["elevation angle", A ? deg(A.el, 1) : null],
                  ["position", num(ref.lat) ? ref.lat.toFixed(5) + ", " + ref.lon.toFixed(5) + " (as broadcast, unverified)" : "-"],
                  ["course", num(ref.course) ? deg(ref.course, 0) : null],
                  ["speed", num(ref.speed_kt) ? ref.speed_kt.toFixed(0) + " kt" : null],
                  ["status", ref.status || null],
                  ["comment", ref.comment || null],
                  ["trail", np + " points over " + (span / 3600).toFixed(1) + " h, " + (ref.moving ? "moving" : "stationary")],
                  ["heard via", lv.via ? (lv.direct ? "direct (" + lv.via + ")" : "digipeater " + lv.via) : null],
                  ["level", num(lv.level) ? String(lv.level) : null],
                  ["last heard", age(ref.last_seen, now) + " ago (shown for " + winText(aprsWin()) + " after its last packet)"]]);
      openTab("APRS");
    } else if (s.kind === "ble" || s.kind === "wifi") {
      var isBle = s.kind === "ble", gl = trendGlyph(ref.trend);
      H.set("radar-side-name", isBle ? (ref.name ? "\"" + ref.name + "\" " : "") + ref.addr
                                     : (ref.ssid ? "\"" + ref.ssid + "\" " : "") + ref.mac);
      kvRows(kv, [["family", isBle ? "BLE advertiser (the BLE receivers)" : "Wi-Fi " + (ref.kind === "ap" ? "access point" : "station") + " (the monitor radio)"],
                  [isBle ? "address" : "MAC", isBle ? ref.addr + " (type " + ref.addr_type + ", " + ref.iface + ")" : ref.mac],
                  [isBle ? "name" : "SSID", isBle ? ref.name || "-" : ref.ssid || (ref.kind === "ap" ? "- (hidden)" : null)],
                  ["distance", (num(ref.m) ? "~" + metres(ref.m) : "- (the band's nominal " + metres(devM(ref)) + ")") + ", " + ref.band],
                  ["trend", ref.trend ? ref.trend + (gl ? " " + gl : "") : "-"],
                  ["RSSI", num(ref.rssi) ? ref.rssi + " dBm" : "-"],
                  ["last seen", age(isBle ? ref.last_seen : ref.ts, now) + " ago"],
                  ["placement", "distance from signal strength; no bearing: drawn on the north axis"]]);
      openTab(isBle ? "BLE Devices" : "Devices");
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
    } else if (s.kind === "fleet") {
      var fr = ref.row, nr = fr.nearest || {};
      H.set("radar-side-name", (fr.label ? "\"" + fr.label + "\" " : "") + fr.key);
      var rows = [["family", (FLEET_KIND[ref.kind] || ref.kind) + ", heard at " + fr.sites.length + " sites"]];
      fr.sites.forEach(function (st) {
        rows.push([siteWord(st.site), st.rssi + " dBm, ~" + metres(st.range_m) + " (" + metres(st.lo_m) + " to " + metres(st.hi_m) +
                   ", \u00b1" + st.sigma_db + " dB" + (st.calibrated ? "" : ", receiver not calibrated") + ")"]);
      });
      kvRows(kv, rows.concat([
        ["nearer", nr.within_band ? "neither (" + nr.by_db + " dB, inside \u00b1" + nr.sigma_db + ")"
                                  : siteWord(nr.site) + " by " + nr.by_db + " dB (\u00b1" + nr.sigma_db + ") than " + siteWord(nr.than)],
        ["method", String(fr.method).replace("_", " ") + ", " + (fr.candidates || []).length + " candidates"],
        ["area drawn", ref.form === "fix" ? "a least-squares fit's disc, radius " + metres(ref.shapes[0].hi)
                       : ref.form === "bands" ? "where every site's one-sigma band overlaps"
                       : "the nearer site's side, within its band"],
        ["band", "\u00b1" + metres(fr.band_m) + " over a " + metres(fr.baseline_m) + " baseline" + (fr.coarse ? ": coarse, a side not a point" : "")],
        ["last heard", age(now - fr.age_s, now) + " ago"],
        ["placement", "range from signal strength at each sloth (ITU-R P.1238, power assumed): where it may be, not where it is"]]));
      openTab("Fleet");
    }
  }
  // "open in <tab>": the family's tab, then its own selection.
  function openSel() {
    var s = S.sel, ref = selRef();
    if (!s || !ref) return;
    if (s.kind === "sat") { H.show("gnss"); if (window.SlothGnss && SlothGnss.select) SlothGnss.select(ref.gnssid, ref.prn); }
    else if (s.kind === "adsb") { H.show("adsb"); if (window.SlothAdsb && SlothAdsb.select) SlothAdsb.select(ref.hex); }
    else if (s.kind === "aprs") { H.show("aprs"); if (window.SlothAprs && SlothAprs.select) SlothAprs.select(ref.kind === "object" ? ref.via : ref.key); }
    else if (s.kind === "ring") H.show(s.key.fam === "ble" ? "ble" : "devices");
    else if (s.kind === "ble") { H.show("ble"); H.openBleDrawer(ref.addr, ref.addr_type, ref.iface); }
    else if (s.kind === "wifi") { H.show("devices"); H.openDrawer(ref.mac); }
    else if (s.kind === "fleet") H.show("fleet");
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
    var stn = aprsEntities(now, aprsWin()).length, rd = S.radar;
    h.appendChild(H.el("span", "", "  " + sats + " satellites, " + air + " aircraft, " + stn + " APRS" +
                       (rd && rd.wifi ? ", Wi-Fi " + rd.wifi.estimated + " in bands" : "") +
                       (rd && rd.ble ? ", BLE " + rd.ble.estimated : "")));
    var errs = Object.keys(S.errs).map(function (k) { return k + ": " + S.errs[k]; });
    if (errs.length) h.appendChild(H.el("span", "h2", "  " + errs.join("; ")));
  }
  function caption() {
    var c = centre(), now = nowOf(S.gnss), p = S.placed || {}, rd = S.radar, local = H.scope() === "local";
    var parts = ["sources /api/gnss 5 s" + (local ? "" : ", /api/adsb 5 s, /api/aprs 5 s, /api/aprs/tracks 24 h 60 s, /api/radar 10 s") +
                 ", /api/gnss/tracks " + TRAIL_H + " h 60 s"];
    parts.push("sensor position " + (c ? c.from + (num(c.age) ? " " + age(now - c.age, now) + " ago" : "") : "none"));
    parts.push("range log 0.3 m–300 km; height is true elevation angle");
    parts.push("satellites " + (p.sats || 0) + " placed" + (p.satsNo ? ", " + p.satsNo + " without az/el" : ""));
    if (!local) {
      parts.push("aircraft " + (p.air || 0) + " placed" + (p.airNo ? ", " + p.airNo + " unplaced" : ""));
      parts.push("APRS: " + (p.aprsN || 0) + " in the last " + winText(aprsWin()) + " (" + (p.aprsMoving || 0) +
                 " moving, trails 24 h), " + (p.aprsObj || 0) + " objects" + (p.aprsNo ? ", " + p.aprsNo + " unplaced" : "") +
                 (S.atrkErr ? " (sloth.db: " + S.atrkErr + ")" : ""));
      if (rd && (rd.wifi || rd.ble)) {
        parts.push((rd.wifi ? rd.wifi.estimated : 0) + " Wi-Fi, " + (rd.ble ? rd.ble.estimated : 0) + " BLE in bands (far drawn at 100 m, nominal)");
        parts.push((rd.wifi ? rd.wifi.none : 0) + " Wi-Fi, " + (rd.ble ? rd.ble.none : 0) + " BLE without a distance estimate");
        parts.push("devices: " + (p.ble || 0) + " of " + (rd.ble ? rd.ble.estimated : 0) + " BLE, " + (p.wifi || 0) + " of " +
                   (rd.wifi ? rd.wifi.estimated : 0) + " Wi-Fi shown (most recent), on the north axis: no bearing");
      }
      parts.push("ticks are speed and heading (aircraft gs/track, APRS speed/course); Wi-Fi and BLE have neither, " +
                 "their arrow is sloth's trend (\u2198 approaching, \u2192 steady, \u2197 leaving)");
      parts.push("distance from signal strength is an estimate; a ring is where the device may be, not where it is");
      var fn = p.fleet || { fix: 0, bands: 0, side: 0, none: 0 };
      if (S.fpeers > 0)
        parts.push(!S.fleetOn ? "fleet areas off" : !fleetPeers() ? "fleet areas: no other sloth with a position yet"
                   : !c ? "fleet areas need a sensor position"
                   : "fleet areas from /api/fleet/locate 30 s: " + (fn.fix + fn.bands + fn.side) + " drawn (" + fn.bands +
                     " where the sites' bands overlap, " + fn.fix + " least-squares discs, " + fn.side + " a side only), " + fn.none +
                     " with no side; each where it may be, not where it is");
      if (S.fleetErr) parts.push("fleet: " + S.fleetErr);
    } else {
      parts.push("Local: the passive radios' families are not read");
    }
    H.set("radar-cap", parts.join("; "));
  }

  // ── loading: the lent scoped getJSON for every fetch ─────────────
  function after() { header(); panel(); dirty(); caption(); }
  function loadSelTrack() {
    var s = S.sel;
    if (!s || s.kind !== "aprs" || s.key.indexOf("station|") !== 0 || H.scope() === "local") return;
    var my = ++S.sgen, id = s.key, call = id.slice(8);
    H.getJSON("/api/aprs?call=" + encodeURIComponent(call)).then(function (j) {
      if (my !== S.sgen || j.out_of_scope || !S.sel || S.sel.key !== id) return;
      S.selTrack = j.station && Array.isArray(j.station.track_pts) ? j.station.track_pts : null;
      dirty();
    }).catch(function () { /* the mark still shows; the next poll retries */ });
  }
  // The three kinds at once; an answer that fails is left out and named
  // in the caption.
  function loadFleet() {
    S.fleetAt = Date.now();
    S.fleetErr = "";
    var fg = ++S.fgen;
    Promise.all(FLEET_KINDS.map(function (k) {
      return H.getJSON("/api/fleet/locate?kind=" + k + "&limit=" + FLEET_LIMIT).catch(function (e) {
        if (fg === S.fgen) S.fleetErr = msg(e);
        return null;
      });
    })).then(function (all) {
      if (fg !== S.fgen) return;
      S.fleet = all;
      fleetBtn();
      after();
    });
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
      S.adsb = S.aprs = S.radar = S.atrk = null;
      S.radarAt = S.atrkAt = 0;
      S.fleet = null;
      S.fleetAt = 0;
      fleetBtn();
      after();
      return;
    }
    // The peers, once a page: the fleet is read only with one.
    if (S.fpeers === -1) {
      S.fpeers = -2;
      H.getJSON("/api/health").then(function (j) {
        S.fpeers = j && j.fleet && Array.isArray(j.fleet.peers) ? j.fleet.peers.length : 0;
        fleetBtn();
        if (fleetWanted() && visible()) loadFleet();
      }).catch(function () { S.fpeers = -1; });
    }
    if (fleetWanted() && Date.now() - S.fleetAt > FLEET_MS) loadFleet();
    // fleet=0: the dome is this receiver's sky; another sloth host's
    // aircraft (the ADS-B tab's grey rows) has no bearing from here.
    H.getJSON("/api/adsb?fleet=0").then(function (j) {
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
    if (Date.now() - S.atrkAt > ATRK_MS) {
      S.atrkAt = Date.now();
      var ag = ++S.agen;
      H.getJSON("/api/aprs/tracks?hours=" + ATRK_H).then(function (j) {
        if (ag !== S.agen) return;
        S.atrk = j.out_of_scope ? null : j;
        S.atrkErr = j.have === false ? "no APRS tables yet" : "";
        after();
      }).catch(function (e) {
        if (ag !== S.agen) return;
        S.atrk = null;
        S.atrkErr = msg(e) === "no_sloth_db" ? "trails need --sloth-db" : msg(e);
        after();
      });
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
    // Kept only when off: absent is on.
    S.fleetOn = H.prefGet("radar.fleet") !== false;
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
      if (!dr) {
        // Hover: a device dot under the pointer shows its label.
        var pt = canvasPoint(ev, cv), pk = pickAt(pt[0], pt[1], true);
        var hv = pk && (pk.kind === "ble" || pk.kind === "wifi" || pk.kind === "fleet") ? pk : null;
        var was = S.hover ? S.hover.kind + "|" + S.hover.key : "", now = hv ? hv.kind + "|" + hv.key : "";
        if (was !== now) { S.hover = hv; dirty(); }
        return;
      }
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
        var pt = canvasPoint(ev, cv), hit = pickAt(pt[0], pt[1], !S.sel);
        if (hit) select(hit.kind, hit.key); else select(null);
      } else {
        savePrefs();
      }
    }
    cv.addEventListener("pointerup", up);
    cv.addEventListener("pointercancel", up);
    cv.addEventListener("pointerleave", function () { if (S.hover) { S.hover = null; dirty(); } });
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
      else if (k === "f") toggleFull();
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
    // The APRS window: the entities read again and the dome redrawn.
    $("radar-aprs-win").addEventListener("change", function () { S.atrkAt = 0; load(); dirty(); });
    $("radar-fleet").addEventListener("click", function () {
      S.fleetOn = !S.fleetOn;
      H.prefSet("radar.fleet", S.fleetOn ? null : false);
      if (!S.fleetOn && S.sel && S.sel.kind === "fleet") select(null);
      if (fleetWanted() && Date.now() - S.fleetAt > FLEET_MS) loadFleet();
      fleetBtn();
      dirty();
    });
    fleetBtn();
    var fb = $("radar-full");
    fb.hidden = !document.fullscreenEnabled;
    fb.addEventListener("click", toggleFull);
    document.addEventListener("fullscreenchange", function () { if (visible()) dirty(); });
    window.addEventListener("resize", function () { if (visible()) dirty(); });
    panel();
  }

  window.SlothRadar = { init: init, show: show, redraw: dirty };
})();
