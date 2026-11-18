// slothweb: the plan position indicator (PPI) behind the APRS and ADS-B
// positions panels: an ATC-style radar scope centred on the sensor
// (owner requests 2026-11-13: "i want the positions view in aprs to look
// like an air traffic control radar with our GPS loctioin in the
// center", then the same for ADS-B). window.SlothPPI:
//   SlothPPI.centre(gnss)            the sensor's position from an
//                                    /api/gnss answer: a fix under 60 s
//                                    old, else the last fix, else
//                                    --location (radar.js's rule), or null
//   SlothPPI.geo(lat0, lon0, lat, lon)  great-circle range (m), bearing
//   SlothPPI.autoRange(d, ranges, share, dflt)  the smallest range
//                                    holding `share` of the distances d
//   SlothPPI.make(canvas, visible)   a scope: .draw(fn) runs fn(t) each
//                                    frame while the sweep turns (once
//                                    under reduced motion), .scope(spec, t)
//                                    draws one, .pick(x, y) the target id
// North up, each target at its true bearing and ground range from the
// sensor (azimuthal equidistant, so a ring is a true distance). Range
// rings named on the north line in the caller's unit (km for APRS,
// nautical miles for aircraft), a bearing rose, a sweep that re-lights
// each target with an afterglow (stepped alpha, no gradient: R8; still
// under prefers-reduced-motion), a velocity leader, an ATC data block
// on a short leader, history as dots or a line. A target past the range
// sits on the rim, dimmed, its distance in its block. The selection is
// the caller's --signal (R1). The sensor's own coordinates are never
// drawn: the scope takes the centre to place targets and writes no
// number from it. Every string is drawn with fillText, never markup.
(function () {
  "use strict";
  var EARTH_M = 6371008.8, FIX_FRESH_S = 60, SWEEP_MS = 6000, GLOW_MS = 2000;
  var PICK_PX = 10, FRAME_MS = 33, RINGS = 5;
  var mq = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
  function still() { return !!(mq && mq.matches); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return v && v.trim() ? v.trim() : fallback;
  }
  function pad3(d) { return ("00" + d).slice(-3); }
  function fmt(v) { return v < 10 && v % 1 ? (v < 1 ? v.toFixed(2) : v.toFixed(1)) : String(Math.round(v)); }

  // The sensor's position: the fix, else --location, else none.
  function centre(j) {
    if (!j) return null;
    var now = num(j.now) ? j.now : Math.floor(Date.now() / 1000), f = j.fix, l = j.loc;
    if (f && num(f.mode) && f.mode >= 2 && num(f.lat) && num(f.lon) && num(f.ts) && now - f.ts <= FIX_FRESH_S)
      return { lat: f.lat, lon: f.lon, from: "gps fix", age: now - f.ts };
    if (l && num(l.lat) && num(l.lon))
      return { lat: l.lat, lon: l.lon, from: l["src"] === "gps" ? "last gps fix" : "--location",
               age: num(l.ts) ? now - l.ts : null };
    return null;
  }
  // Great-circle ground range (m) and initial bearing (deg true).
  function geo(lat0, lon0, lat, lon) {
    var d = Math.PI / 180, p0 = lat0 * d, p1 = lat * d, dl = (lon - lon0) * d, dp = p1 - p0;
    var a = Math.sin(dp / 2) * Math.sin(dp / 2) + Math.cos(p0) * Math.cos(p1) * Math.sin(dl / 2) * Math.sin(dl / 2);
    var range = 2 * EARTH_M * Math.atan2(Math.sqrt(a), Math.sqrt(Math.max(0, 1 - a)));
    var y = Math.sin(dl) * Math.cos(p1), x = Math.cos(p0) * Math.sin(p1) - Math.sin(p0) * Math.cos(p1) * Math.cos(dl);
    return { range: range, az: (Math.atan2(y, x) / d + 360) % 360 };
  }
  // The smallest step holding `share` of the distances, so one far
  // target does not shrink the rest to the centre; the others sit on
  // the rim with their distance.
  function autoRange(d, ranges, share, dflt) {
    var ks = d.filter(num).sort(function (x, y) { return x - y; });
    if (!ks.length) return dflt;
    var far = ks[Math.max(0, Math.ceil(ks.length * share) - 1)];
    for (var i = 0; i < ranges.length; i++) if (ranges[i] >= far * 1.08) return ranges[i];
    return ranges[ranges.length - 1];
  }

  function make(canvas, visible) {
    var marks = [], raf = 0, frameAt = 0, drawFn = null;
    function frame(t) {
      raf = 0;
      if (!drawFn || !visible() || document.hidden) return;
      if (t - frameAt >= FRAME_MS || still()) {
        frameAt = t;
        marks = [];
        if (drawFn(t) === false) return;   // the static fallback: no sweep
      }
      if (!still()) raf = requestAnimationFrame(frame);
    }
    function draw(fn) {
      drawFn = fn;
      if (still() || !raf) { if (raf) cancelAnimationFrame(raf); raf = requestAnimationFrame(frame); }
    }
    function pick(x, y) {
      var best = null, bd = PICK_PX * PICK_PX;
      marks.forEach(function (m) { var dd = (m.x - x) * (m.x - x) + (m.y - y) * (m.y - y); if (dd <= bd) { bd = dd; best = m; } });
      return best ? best.id : null;
    }
    function mark(x, y, id) { marks.push({ x: x, y: y, id: id }); }

    // spec: { centre, range (in unit), unit: { name, km }, targets: [{ id,
    // lat, lon, color, fill, shape ("circle" | "tri"), heading, lead: {
    // course, kt, s }, lines: [text], textColor, alpha, ring, picked }],
    // tracks: [{ pts: [[lat, lon, color?]], style ("line" | "dots"),
    // color, width, alpha }], empty }. Returns { range, beyond }.
    function scope(spec, t) {
      var c = canvas, ctr = spec.centre;
      var dpr = window.devicePixelRatio || 1;
      var W = Math.max(240, c.clientWidth || 480), H = Math.max(320, Math.min(620, Math.round(W * 0.8)));
      if (c.width !== Math.round(W * dpr) || c.height !== Math.round(H * dpr)) {
        c.width = Math.round(W * dpr); c.height = Math.round(H * dpr); c.style.height = H + "px";
      }
      var g = c.getContext("2d");
      if (!g) return null;
      g.setTransform(dpr, 0, 0, dpr, 0, 0);
      g.clearRect(0, 0, W, H);
      var ph = cssVar("--phosphor", "#6bffcc"), phd = cssVar("--phosphor-dim", "#2b8f74");
      var ink = cssVar("--ink", "currentColor");
      var cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 30, d2r = Math.PI / 180;
      var unit = spec.unit, rk = spec.range * unit.km, pxKm = R / rk;
      function P(az, km) {
        var r = Math.min(km, rk) * pxKm;
        return { x: cx + r * Math.sin(az * d2r), y: cy - r * Math.cos(az * d2r) };
      }
      function PL(lat, lon) { var q = geo(ctr.lat, ctr.lon, lat, lon); return P(q.az, q.range / 1000); }
      // Rings, the outer one the range, each named on the north line.
      g.lineWidth = 1; g.strokeStyle = phd; g.fillStyle = phd; g.font = "10px monospace";
      var i, dg;
      for (i = 1; i <= RINGS; i++) {
        g.globalAlpha = i === RINGS ? 0.9 : 0.5;
        g.beginPath(); g.arc(cx, cy, R * i / RINGS, 0, Math.PI * 2); g.stroke();
      }
      g.globalAlpha = 0.9; g.textAlign = "left"; g.textBaseline = "bottom";
      for (i = 1; i <= RINGS; i++) g.fillText(fmt(spec.range * i / RINGS) + " " + unit.name, cx + 3, cy - R * i / RINGS - 1);
      g.globalAlpha = 0.25;
      g.beginPath(); g.moveTo(cx - R, cy); g.lineTo(cx + R, cy); g.moveTo(cx, cy - R); g.lineTo(cx, cy + R); g.stroke();
      // The bearing rose: 5, 10 and 30 degree ticks outside the rim.
      g.globalAlpha = 0.8;
      for (dg = 0; dg < 360; dg += 5) {
        var sn = Math.sin(dg * d2r), cs = Math.cos(dg * d2r), len = dg % 30 === 0 ? 9 : dg % 10 === 0 ? 6 : 3;
        g.beginPath(); g.moveTo(cx + R * sn, cy - R * cs); g.lineTo(cx + (R + len) * sn, cy - (R + len) * cs); g.stroke();
      }
      g.fillStyle = ph; g.textAlign = "center"; g.textBaseline = "middle";
      for (dg = 0; dg < 360; dg += 30)
        g.fillText(dg === 0 ? "N" : pad3(dg), cx + (R + 19) * Math.sin(dg * d2r), cy - (R + 19) * Math.cos(dg * d2r));
      // The sweep: one line and three fading steps behind it.
      var sw = still() ? -1 : (t % SWEEP_MS) / SWEEP_MS * 360;
      if (sw >= 0) {
        g.strokeStyle = ph;
        [[0, 0.9, 1.5], [2, 0.35, 1], [4, 0.18, 1], [7, 0.08, 1]].forEach(function (s) {
          var a = (sw - s[0]) * d2r;
          g.globalAlpha = s[1]; g.lineWidth = s[2];
          g.beginPath(); g.moveTo(cx, cy); g.lineTo(cx + R * Math.sin(a), cy - R * Math.cos(a)); g.stroke();
        });
        g.lineWidth = 1;
      }
      // Afterglow: full as the sweep passes, decaying to 0.35 by its return.
      function glow(az) {
        if (sw < 0) return 1;
        var ms = ((sw - az + 360) % 360) / 360 * SWEEP_MS;
        return 0.35 + 0.65 * Math.exp(-ms / GLOW_MS);
      }
      // History: a line, or ATC history dots, each point its own colour
      // when the caller gives one (altitude on the heat ramp).
      (spec.tracks || []).forEach(function (tr) {
        var pts = (tr.pts || []).filter(function (p) { return num(p[0]) && num(p[1]); });
        if (!pts.length) return;
        g.globalAlpha = num(tr.alpha) ? tr.alpha : 0.8;
        g.lineWidth = tr.width || 1.5;
        var prev = null;
        pts.forEach(function (p) {
          var q = PL(p[0], p[1]), col = p[2] || tr.color;
          if (tr.style === "dots") { g.fillStyle = col; g.fillRect(q.x - 1, q.y - 1, 2, 2); }
          else if (prev) { g.strokeStyle = col; g.beginPath(); g.moveTo(prev.x, prev.y); g.lineTo(q.x, q.y); g.stroke(); }
          prev = q;
        });
        g.lineWidth = 1;
      });
      // The sensor: a cross at the centre.
      g.globalAlpha = 1; g.strokeStyle = ink;
      g.beginPath(); g.moveTo(cx - 5, cy); g.lineTo(cx + 5, cy); g.moveTo(cx, cy - 5); g.lineTo(cx, cy + 5); g.stroke();
      // Targets, the selection last so it draws on top.
      var beyond = 0, tg = (spec.targets || []).filter(function (o) { return num(o.lat) && num(o.lon); });
      tg.sort(function (x, y) { return (x.picked ? 1 : 0) - (y.picked ? 1 : 0); });
      g.font = "11px monospace"; g.textAlign = "left"; g.textBaseline = "alphabetic";
      tg.forEach(function (o) {
        var q = geo(ctr.lat, ctr.lon, o.lat, o.lon), km = q.range / 1000, p = P(q.az, km), out = km > rk;
        if (out) beyond++;
        var al = glow(q.az) * (num(o.alpha) ? o.alpha : 1) * (out ? 0.6 : 1);
        g.globalAlpha = al; g.strokeStyle = o.color; g.fillStyle = o.color; g.lineWidth = 1.5;
        var sz = o.picked ? 5 : 3.5;
        g.beginPath();
        if (o.shape === "tri") {
          // ▲ turned to the heading (north when none).
          var h = (num(o.heading) ? o.heading : 0) * d2r, s2 = sz + 1.5;
          for (var k = 0; k < 3; k++) {
            var a2 = h + k * 2 * Math.PI / 3, rr = k ? s2 * 0.8 : s2 * 1.5;
            var vx = p.x + rr * Math.sin(a2), vy = p.y - rr * Math.cos(a2);
            if (k) g.lineTo(vx, vy); else g.moveTo(vx, vy);
          }
          g.closePath();
        } else {
          g.arc(p.x, p.y, sz, 0, Math.PI * 2);
        }
        if (o.fill) g.fill(); else g.stroke();
        if (o.ring) {
          g.strokeStyle = o.ring; g.globalAlpha = 1;
          g.beginPath(); g.arc(p.x, p.y, 10, 0, Math.PI * 2); g.stroke();
          g.strokeStyle = o.color; g.globalAlpha = al;
        }
        var ld = o.lead;
        if (ld && !out && num(ld.course) && num(ld.kt) && ld.kt > 0) {
          var L = Math.max(8, ld.kt * 1.852 * ld.s / 3600 * pxKm), ca = ld.course * d2r;
          g.beginPath(); g.moveTo(p.x, p.y); g.lineTo(p.x + L * Math.sin(ca), p.y - L * Math.cos(ca)); g.stroke();
        }
        // The data block, up and right on a short leader.
        g.lineWidth = 1; g.globalAlpha = Math.max(al, o.picked || o.ring ? 1 : 0.55);
        g.beginPath(); g.moveTo(p.x + 4, p.y - 4); g.lineTo(p.x + 11, p.y - 11); g.stroke();
        var lines = (o.lines || []).slice();
        if (out) lines.push(fmt(km / unit.km) + " " + unit.name + " out");
        g.fillStyle = o.textColor || ink;
        lines.forEach(function (s, n) { g.fillText(s, p.x + 13, p.y - 12 + n * 12 - (lines.length - 1) * 12); });
        mark(p.x, p.y, o.id);
      });
      g.globalAlpha = 1;
      if (!tg.length && spec.empty) {
        g.fillStyle = cssVar("--tui-dim", "#888"); g.textAlign = "center";
        g.fillText(spec.empty, cx, cy + 22);
      }
      return { range: spec.range, beyond: beyond };
    }
    canvas.addEventListener("click", function (e) {
      if (!scopeApi.onPick) return;
      var r = canvas.getBoundingClientRect(), id = pick(e.clientX - r.left, e.clientY - r.top);
      if (id !== null) scopeApi.onPick(id);
    });
    var scopeApi = { draw: draw, scope: scope, pick: pick, mark: mark, onPick: null };
    return scopeApi;
  }

  window.SlothPPI = { centre: centre, geo: geo, autoRange: autoRange, make: make, still: still, fmt: fmt, pad3: pad3 };
})();
