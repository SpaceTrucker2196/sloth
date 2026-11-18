// slothweb: the isometric waterfall (#224, owner 2026-11-16: "Make the
// WiFi and ble spectrums iso metric like the spectrum tab").
// window.SlothIso, the projection and the back-to-front row painter the
// Spectrum tab drew with since 2026-11-13, moved here so the Spectrum,
// WiFi and BLE Devices tabs draw one picture the same way:
//   SlothIso.theme(g)               the heat stops and inks, read from
//                                   the theme at each draw
//   SlothIso.scheme()               the identity colours (iso.css):
//                                   band shades and class hues
//   SlothIso.layout(o)              the projection: the plot's width, the
//                                   ridge height and the depth offsets
//   SlothIso.rails(g, T, geo)       the floor's two side rails
//   SlothIso.paint(g, T, geo, o)    the rows, back to front; heat
//                                   coloured, or o.segments / o.cap
//   SlothIso.hit(geo, x, y)         the row under a point
//   SlothIso.colAt(geo, i, x)       that row's column under it
//   SlothIso.frame(cv, st, r, ov)   the offscreen picture and an overlay
//   SlothIso.grid(cv, st, o)        a cell grid (columns across, time
//                                   cells receding), axes and all; a
//                                   column's floor, cap and segments
//                                   coloured when the caller says; a
//                                   lane of counts under the floor and
//                                   a picked set of columns and cells
//   SlothIso.at(cv, st, ev)         the grid cell under a pointer
//   SlothIso.tip(box, lines, ev)    the hover tooltip's lines
// A plain canvas, no library (the page's CSP loads none); every string
// is drawn with fillText or set with textContent.
(function () {
  "use strict";
  function num(v) { return typeof v === "number" && isFinite(v); }
  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return v && v.trim() ? v.trim() : fallback;
  }

  // ── colour ───────────────────────────────────────────────────────
  // The palette's four heat stops, read from the theme at each draw so
  // the light theme gets its own; interpolated through a 1x1 canvas.
  function rgbOf(g, c) {
    g.fillStyle = "#000"; g.fillStyle = c;
    var s = g.fillStyle;
    if (s.charAt(0) === "#") return [parseInt(s.substr(1, 2), 16), parseInt(s.substr(3, 2), 16), parseInt(s.substr(5, 2), 16)];
    var m = s.match(/(\d+(\.\d+)?)/g);
    return m ? [+m[0], +m[1], +m[2]] : [128, 128, 128];
  }
  function theme(g) {
    return {
      heat: [rgbOf(g, cssVar("--heat-0", "#2b8f74")), rgbOf(g, cssVar("--heat-1", "#6bffcc")),
             rgbOf(g, cssVar("--heat-2", "#ff8c26")), rgbOf(g, cssVar("--heat-3", "#ff3f3f"))],
      bg: rgbOf(g, cssVar("--panel", "#0e0817")),
      ink: cssVar("--ink", "#e8e2f2"), muted: cssVar("--muted", "#8a82a0"),
      rule: cssVar("--rule", "#163a30"), signal: cssVar("--signal", "#ff8c26"),
      data: cssVar("--data", "#4cebff"), faint: cssVar("--faint", "#5a536e")
    };
  }
  // The identity colours (iso.css; owner 2026-11-17: "color code
  // finding by band channel and ssid"): a hue per BLE class slug. A WiFi
  // channel's is the page's one channel colour (chan.js, 2026-11-18),
  // which app.js reads itself.
  function scheme() {
    return {
      cls: { "b:phone": cssVar("--iso-c-phone", "#5b9bff"), "b:wear": cssVar("--iso-c-wear", "#6fdc6f"),
             "b:tag": cssVar("--iso-c-tag", "#ff6a3d"), "b:hid": cssVar("--iso-c-hid", "#f2d240"),
             "b:bcn": cssVar("--iso-c-bcn", "#40e0f0"), "b:iot": cssVar("--iso-c-iot", "#c07cff"),
             "b:unk": cssVar("--iso-c-unk", "#8a8a96") },
      muted: cssVar("--muted", "#8a82a0")
    };
  }
  // A shade step of a colour: t of the way from the panel's ground to
  // it (1 the colour itself), for shades within a hue family.
  function toward(g, T, c, t) { return css(mix(T.bg, rgbOf(g, c), t)); }
  function mix(a, b, t) { return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t]; }
  function heatRGB(T, f) {
    f = Math.max(0, Math.min(1, f));
    var x = f * 3, i = Math.min(2, Math.floor(x));
    return mix(T.heat[i], T.heat[i + 1], x - i);
  }
  function css(c, a) {
    return "rgba(" + Math.round(c[0]) + "," + Math.round(c[1]) + "," + Math.round(c[2]) + "," + (a === undefined ? 1 : a) + ")";
  }

  // ── the projection ───────────────────────────────────────────────
  // The newest row in front, along the bottom; each older one further
  // back, right and up, by its depth (0 the front, 1 the back). The
  // depth the rows take grows and the ridge height shrinks with the row
  // count, so 3 rows are tall ridges and 288 a terrain.
  // o: {W, Hh, n, L, R, top, bottom, deep}; deep: a time axis or more
  // than a dozen rows.
  function layout(o) {
    var n = o.n, L = o.L, R = o.R, W = o.W, avail = o.Hh - o.top - o.bottom;
    var DXT, DYT;
    if (o.deep) {
      // The depth axis is time, its share of the height growing with
      // the rows it holds (3 rows ~30%, 288 ~65%).
      var share = Math.min(0.65, 0.3 + 0.07 * Math.log(Math.max(n, 3) / 3) / Math.LN2);
      DYT = avail * share; DXT = Math.min((W - L - R) * 0.16, DYT * 0.9);
    } else {
      // A few rows: the original ridge spacing.
      DXT = Math.min(28, (W - L - R) * 0.04) * (n - 1); DYT = Math.min(30, avail * 0.12) * (n - 1);
    }
    var PW = Math.max(100, W - L - R - DXT), base0 = o.Hh - o.bottom;
    var RH = Math.max(40, base0 - o.top - DYT);
    return { L: L, PW: PW, DXT: DXT, DYT: DYT, base0: base0, RH: RH, n: n, top: o.top,
             rowOx: [], rowOy: [], ridges: [], cols: 0, front: [] };
  }
  function ox(geo, d) { return geo.L + d * geo.DXT; }
  function oy(geo, d) { return geo.base0 - d * geo.DYT; }
  function rails(g, T, geo) {
    var L = geo.L, PW = geo.PW, base0 = geo.base0;
    g.strokeStyle = T.rule; g.lineWidth = 1;
    g.beginPath(); g.moveTo(L, base0); g.lineTo(L + geo.DXT, base0 - geo.DYT);
    g.moveTo(L + PW, base0); g.lineTo(L + PW + geo.DXT, base0 - geo.DYT); g.stroke();
  }

  // ── the rows, back to front ──────────────────────────────────────
  // Each column filled down to its own baseline, so a front ridge hides
  // what is behind it, as a 3-D surface would; past ~24 rows a column's
  // body is darkened and its top capped in the full heat colour, so
  // every ridge keeps an edge against the one behind it, and only every
  // few ridges get an outline, so a dense range reads as a surface and
  // not a hairball. Colour strings are cached per level step: a 24 h
  // Spectrum range paints a few hundred thousand columns.
  // o: {cols, depth(i), value(i, c) -> 0..1 (0: nothing), gap (px per
  // side) and step (outline along the tops) for discrete columns,
  // after(i, x0, y0) once a row is down; segments(i, c) -> [{f, color,
  // alpha}] stacks a column's body bottom up, each f its share of the
  // height, in its colour (alpha 0..1 fades it to the ground), and
  // cap(c) -> a colour for the column's top edge}. With neither, the
  // heat ramp's calls exactly as before (the Spectrum tab's picture).
  function paint(g, T, geo, o) {
    var n = geo.n, cols = o.cols, PW = geo.PW, RH = geo.RH, c, k;
    geo.cols = cols;
    var order = [];
    for (var i = 0; i < n; i++) order.push(i);
    order.sort(function (a, b) { return o.depth(b) - o.depth(a); });   // back first
    var dense = n > 24, pal = [], cap = [];
    for (k = 0; k <= 64; k++) {
      pal.push(css(mix(T.bg, heatRGB(T, k / 64), dense ? 0.12 + 0.5 * k / 64 : 0.35 + 0.65 * k / 64)));
      cap.push(css(heatRGB(T, k / 64)));
    }
    var gp = o.gap ? Math.min(o.gap, PW / cols * 0.2) : 0;
    var seg = o.segments ? segPainter(g, T, dense) : null, capOf = o.cap ? colorCache(g) : null;
    var every = n <= 24 ? 1 : Math.ceil(n / 24);
    for (var r = 0; r < n; r++) {
      var idx = order[r], d = o.depth(idx), x0 = ox(geo, d), y0 = oy(geo, d), ridge = new Float32Array(cols);
      var front = r === n - 1;
      for (c = 0; c < cols; c++) {
        var f = o.value(idx, c);
        f = num(f) ? Math.max(0, Math.min(1, f)) : 0;
        ridge[c] = f;
        var hpx = f * RH;
        if (hpx < 0.5) continue;
        var sg = seg ? o.segments(idx, c) : null, cc = capOf ? capOf(o.cap(c)) : null;
        if (sg && sg.length) seg(sg, f, x0 + c * PW / cols + gp, y0, PW / cols + 0.6 - 2 * gp, hpx);
        else {
          g.fillStyle = pal[Math.round(f * 64)];
          g.fillRect(x0 + c * PW / cols + gp, y0 - hpx, PW / cols + 0.6 - 2 * gp, hpx);
        }
        if (cc) { g.fillStyle = cc; g.fillRect(x0 + c * PW / cols + gp, y0 - hpx, PW / cols + 0.6 - 2 * gp, Math.min(dense ? 1.5 : 2, hpx)); }
        else if (dense) { g.fillStyle = cap[Math.round(f * 64)]; g.fillRect(x0 + c * PW / cols + gp, y0 - hpx, PW / cols + 0.6 - 2 * gp, Math.min(1.5, hpx)); }
      }
      geo.rowOx[idx] = x0; geo.rowOy[idx] = y0; geo.ridges[idx] = ridge;
      // The baseline under the ridge, so a quiet row still shows.
      g.strokeStyle = T.rule; g.lineWidth = 1;
      if (n <= 48 || front) { g.beginPath(); g.moveTo(x0, y0 + 0.5); g.lineTo(x0 + PW, y0 + 0.5); g.stroke(); }
      if (front || (n - 1 - r) % every === 0) {
        g.beginPath();
        for (c = 0; c < cols; c++) {
          var px = x0 + (c + 0.5) * PW / cols, py = y0 - ridge[c] * RH;
          if (o.step) {
            // Discrete columns: the outline runs along each column's top.
            var sx = x0 + c * PW / cols + gp;
            if (c) g.lineTo(sx, py); else g.moveTo(sx, py);
            g.lineTo(sx + PW / cols - 2 * gp, py);
          } else if (c) g.lineTo(px, py); else g.moveTo(px, py);
        }
        g.strokeStyle = front ? T.ink : css(heatRGB(T, 0.6), n > 24 ? 0.55 : 0.9);
        g.lineWidth = front ? 1 : 0.8;
        g.stroke();
      }
      if (o.after) o.after(idx, x0, y0);
    }
  }

  // A column's body as segments: each its share of the column's height,
  // bottom up, the last taking what rounding left. The body is the
  // colour blended into the ground by the cell's value (taller,
  // stronger; darker in a dense range, as the heat body is) and by the
  // segment's alpha, opaque, so a front ridge still hides the one
  // behind it. Colour strings cached per colour and step.
  function segPainter(g, T, dense) {
    var memo = {};
    function shade(color, t) {
      var q = Math.round(Math.max(0, Math.min(1, t)) * 32), key = color + "|" + q;
      if (!Object.prototype.hasOwnProperty.call(memo, key)) memo[key] = toward(g, T, color, q / 32);
      return memo[key];
    }
    return function (sg, f, x, y0, w, hpx) {
      var body = dense ? 0.5 + 0.4 * f : 0.6 + 0.4 * f, y = y0, left = hpx;
      for (var s = 0; s < sg.length && left > 0; s++) {
        var h = s === sg.length - 1 ? left : Math.min(left, Math.max(0, num(sg[s].f) ? sg[s].f : 0) * hpx);
        if (!(h > 0)) continue;
        g.fillStyle = shade(String(sg[s].color), body * (num(sg[s].alpha) ? sg[s].alpha : 1));
        g.fillRect(x, y - h, w, h);
        y -= h; left -= h;
      }
    };
  }
  function colorCache(g) {
    var memo = {};
    return function (c) {
      if (!c) return null;
      if (!Object.prototype.hasOwnProperty.call(memo, c)) memo[c] = css(rgbOf(g, c));
      return memo[c];
    };
  }

  // ── hit-testing ──────────────────────────────────────────────────
  // The row under the pointer is the frontmost whose painted column
  // covers it (what the eye sees there); off every column, the row
  // whose baseline is nearest.
  function hit(geo, x, y) {
    var best = -1, bestD = Infinity, order = [];
    for (var i = 0; i < geo.n; i++) if (geo.ridges[i]) order.push(i);
    order.sort(function (a, b) { return geo.rowOy[b] - geo.rowOy[a]; });   // front first
    for (var k = 0; k < order.length; k++) {
      var idx = order[k], f = (x - geo.rowOx[idx]) / geo.PW;
      if (f < 0 || f > 1) continue;
      var c = Math.min(geo.cols - 1, Math.floor(f * geo.cols)), oy0 = geo.rowOy[idx];
      if (y <= oy0 + 1 && y >= oy0 - Math.max(2, geo.ridges[idx][c] * geo.RH)) return idx;
      var dd = Math.abs(y - oy0);
      if (dd < bestD) { bestD = dd; best = idx; }
    }
    return best;
  }
  function colAt(geo, idx, x) {
    var f = (x - geo.rowOx[idx]) / geo.PW;
    if (!(f >= 0 && f <= 1)) return -1;
    return Math.min(geo.cols - 1, Math.floor(f * geo.cols));
  }

  // ── the offscreen picture ────────────────────────────────────────
  // The picture is drawn once into an offscreen canvas (st.off, again
  // when st.dirty or the size changes); hover and selection paint over
  // a copy of it. render(off, dpr, W, Hh) in CSS pixels; overlay(g)
  // with the dpr transform set.
  function frame(cv, st, render, overlay) {
    var dpr = window.devicePixelRatio || 1, W = cv.clientWidth || 800, Hh = cv.clientHeight || 460;
    if (cv.width !== Math.round(W * dpr) || cv.height !== Math.round(Hh * dpr)) {
      cv.width = Math.round(W * dpr); cv.height = Math.round(Hh * dpr);
      st.dirty = true;
    }
    if (!st.off) st.off = document.createElement("canvas");
    if (st.dirty || st.off.width !== cv.width || st.off.height !== cv.height) {
      st.off.width = cv.width; st.off.height = cv.height;
      render(st.off, dpr, W, Hh);
      st.dirty = false;
    }
    var g = cv.getContext("2d");
    g.setTransform(1, 0, 0, 1, 0, 0);
    g.clearRect(0, 0, cv.width, cv.height);
    g.drawImage(st.off, 0, 0);
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (overlay) overlay(g);
  }

  // ── a cell grid, isometric ───────────────────────────────────────
  // The WiFi channel waterfall and the BLE Devices tab's two: columns
  // across (channels, classes, advertisers), the time cells receding
  // with the newest in front, height and heat each cell's value on one
  // scale for the whole grid, lo to hi.
  // o: {cols: [{label, short, group, groupShort, groupColor, floor:
  //     {color, dash}, cap}], n, from, col_s, value(k, c) -> number or
  //     null, segments(k, c) -> as paint()'s, lo, hi, ticks, unit, fmt,
  //     clock(ts), sel: {k, c} or null, empty: words when there is
  //     nothing to draw}. A column's floor is a strip under its name
  //     (dashed with dash), its cap its top edge, a group's colour its
  //     name's; the margin under the front row grows for the strip, and
  //     every name is drawn as without it.
  //     o.lane: {name, count(c) -> n, color(c), foot(k, c) -> a colour
  //     or null} (the WiFi tab's clients, owner 2026-11-17): a row under
  //     the floor strip, a diamond a column sized by its count against
  //     the largest, the count beside it where it fits and the lane's
  //     name at left; foot(k, c) a tick at the foot of that cell's
  //     column. The group's rule and name move down under the lane.
  //     o.pick: {cols: [c], color(c), cells: [{k, c}], cellColor}:
  //     those columns' floors traced in color(c) and those cells
  //     marked by a bar across their tops in cellColor (else their
  //     column's), under the selection's outline.
  function gridRender(st) {
    return function (cv, dpr, W, Hh) {
      var o = st.o, g = cv.getContext("2d");
      g.setTransform(dpr, 0, 0, dpr, 0, 0);
      var T = theme(g);
      g.clearRect(0, 0, W, Hh);
      g.font = "10px " + cssVar("--font-mono", "monospace");
      st.geo = null;
      var nc = o.cols.length, n = o.n;
      if (!nc || !n) {
        g.fillStyle = T.muted;
        g.fillText(o.empty || "no data", 16, 24);
        return;
      }
      var grouped = o.cols.some(function (c) { return !!c.group; });
      var floored = o.cols.some(function (c) { return !!c.floor; }), fy = floored ? 7 : 0;
      var lane = o.lane || null, ly = lane ? 14 : 0;
      var geo = layout({ W: W, Hh: Hh, n: n, L: 44, R: 56, top: 14, bottom: (grouped ? 34 : 22) + fy + ly, deep: n > 12 });
      geo.foot = 17 + fy + ly;
      st.geo = geo;
      // A scale with no extent (a caller's hi equal to its lo) is one
      // unit wide, so no tick, height or ridge is NaN.
      var span = o.hi > o.lo ? o.hi - o.lo : 1, PW = geo.PW, base0 = geo.base0, RH = geo.RH, k;
      rails(g, T, geo);
      // The level scale at left.
      g.fillStyle = T.muted; g.strokeStyle = T.rule; g.textAlign = "right";
      var tk = o.ticks || [o.lo, (o.lo + o.hi) / 2, o.hi];
      for (k = 0; k < tk.length; k++) {
        var yy = base0 - (tk[k] - o.lo) / span * RH;
        g.fillText(o.fmt ? o.fmt(tk[k]) : String(tk[k]), geo.L - 4, yy + 3);
        g.beginPath(); g.moveTo(geo.L - 2, yy); g.lineTo(geo.L, yy); g.stroke();
      }
      if (o.unit) {
        g.save(); g.translate(8, base0 - RH / 2); g.rotate(-Math.PI / 2); g.textAlign = "center";
        g.fillText(o.unit, 0, 0); g.restore();
      }
      function depth(i) { return n > 1 ? (n - 1 - i) / (n - 1) : 0; }
      paint(g, T, geo, {
        cols: nc, depth: depth, gap: 1, step: true,
        value: function (i, c) {
          var v = o.value(i, c);
          return num(v) && span > 0 ? (v - o.lo) / span : 0;
        },
        segments: o.segments, cap: o.cols.some(function (c) { return !!c.cap; }) ? function (c) { return o.cols[c].cap; } : null,
        after: lane && lane.foot ? function (i, x0, y0) {
          // Drawn as each row goes down, so a nearer row hides it.
          for (var fc = 0; fc < nc; fc++) {
            var fcol = lane.foot(i, fc);
            if (!fcol) continue;
            g.fillStyle = fcol;
            g.fillRect(x0 + (fc + 0.25) * PW / nc, y0 + 1, Math.max(1, PW / nc * 0.5), 2);
          }
        } : null
      });
      // The time axis up the right rail: a label a label height apart.
      g.fillStyle = T.muted; g.strokeStyle = T.rule; g.textAlign = "left";
      var every = Math.max(1, Math.ceil(16 / Math.max(0.01, geo.DYT / Math.max(1, n - 1))));
      for (k = n - 1; k >= 0; k -= every) {
        var d = depth(k), x = ox(geo, d) + PW, y = oy(geo, d);
        g.beginPath(); g.moveTo(x + 2, y); g.lineTo(x + 6, y); g.stroke();
        g.fillText(o.clock(o.from + k * o.col_s), x + 8, y + 3);
      }
      // The columns' names under the front row, a name where it fits,
      // then each group's name under its span.
      g.textAlign = "center";
      var cw = PW / nc, last = -Infinity, gs = 0;
      // The floor strip under the names: each column's colour across
      // its width, dashed where the caller marks it (DFS).
      for (var fc = 0; floored && fc < nc; fc++) {
        var fl = o.cols[fc].floor;
        if (!fl) continue;
        g.fillStyle = fl.color;
        var fx = geo.L + fc * cw + 0.5, fz = geo.L + (fc + 1) * cw - 0.5;
        if (!fl.dash) { g.fillRect(fx, base0 + 15, Math.max(0.5, fz - fx), 4); continue; }
        for (var dx = fx; dx < fz; dx += 5) g.fillRect(dx, base0 + 15, Math.min(3, fz - dx), 4);
      }
      if (lane) {
        var lcy = base0 + 19 + fy, lmax = 0, lc;
        for (lc = 0; lc < nc; lc++) lmax = Math.max(lmax, num(lane.count(lc)) ? lane.count(lc) : 0);
        // At the left edge: the level axis's labels sit above it.
        g.fillStyle = T.muted; g.textAlign = "left";
        g.fillText(lane.name, 1, lcy + 3);
        g.textAlign = "left";
        for (lc = 0; lc < nc; lc++) {
          var ln = lane.count(lc);
          if (!num(ln) || ln <= 0) continue;
          var lt = String(ln), ltw = g.measureText(lt).width, rr = Math.min(cw * 0.45, 2 + 3 * Math.sqrt(ln / lmax));
          var lx = geo.L + (lc + 0.5) * cw, wide = cw >= ltw + 2 * rr + 4;
          if (wide) lx -= (ltw + 2) / 2;
          g.fillStyle = lane.color(lc);
          g.beginPath(); g.moveTo(lx, lcy - rr); g.lineTo(lx + rr, lcy); g.lineTo(lx, lcy + rr); g.lineTo(lx - rr, lcy);
          g.closePath(); g.fill();
          if (wide) { g.fillStyle = T.ink; g.fillText(lt, lx + rr + 2, lcy + 3); }
        }
        g.textAlign = "center";
      }
      for (var c = 0; c <= nc; c++) {
        if (c < nc) {
          var cx = geo.L + (c + 0.5) * cw, lab = o.cols[c].label, w = g.measureText(lab).width;
          if (w > cw - 2 && o.cols[c].short) { lab = o.cols[c].short; w = g.measureText(lab).width; }
          if (cx - w / 2 > last + 3) {
            g.fillStyle = T.muted;
            g.fillText(lab, cx, base0 + 12);
            last = cx + w / 2;
          }
        }
        if (grouped && (c === nc || (c > gs && o.cols[c].group !== o.cols[gs].group))) {
          var a = geo.L + gs * cw, z = geo.L + c * cw;
          g.strokeStyle = T.rule;
          g.beginPath(); g.moveTo(a + 2, base0 + 18.5 + fy + ly); g.lineTo(z - 2, base0 + 18.5 + fy + ly); g.stroke();
          var gl = o.cols[gs].group || "";
          if (gl && g.measureText(gl).width >= z - a && o.cols[gs].groupShort) gl = o.cols[gs].groupShort;
          if (gl && g.measureText(gl).width < z - a) { g.fillStyle = o.cols[gs].groupColor || T.ink; g.fillText(gl, (a + z) / 2, base0 + 29 + fy + ly); }
          gs = c;
        }
      }
      g.textAlign = "left";
    };
  }
  function gridOverlay(st) {
    return function (g) {
      var geo = st.geo, o = st.o;
      if (!geo) return;
      var T = theme(g);
      function cell(s, color, w) {
        if (!s || s.k < 0 || s.k >= geo.n || s.c < 0 || s.c >= geo.cols || !geo.ridges[s.k]) return;
        var x0 = geo.rowOx[s.k], y0 = geo.rowOy[s.k], cw = geo.PW / geo.cols;
        var h = Math.max(2, geo.ridges[s.k][s.c] * geo.RH);
        g.strokeStyle = color; g.lineWidth = w;
        g.strokeRect(x0 + s.c * cw + 0.5, y0 - h + 0.5, Math.max(1, cw - 1), h);
      }
      var pk = o.pick, fk = geo.n - 1, cwp = geo.PW / geo.cols;
      if (pk && geo.ridges[fk] && geo.ridges[0]) {
        (pk.cols || []).forEach(function (c) {
          if (!(c >= 0 && c < geo.cols)) return;
          // The column's floor from the newest row to the oldest, and its
          // slot under the front row down through the lane.
          g.strokeStyle = pk.color(c); g.lineWidth = 3;
          g.beginPath(); g.moveTo(geo.rowOx[fk] + (c + 0.5) * cwp, geo.rowOy[fk] + 2);
          g.lineTo(geo.rowOx[0] + (c + 0.5) * cwp, geo.rowOy[0] + 2); g.stroke();
          g.lineWidth = 2;
          g.strokeRect(geo.L + c * cwp + 1, geo.base0 + 2, Math.max(1, cwp - 2), geo.foot || 17);
        });
        // A cell it was named in: a bar across its column's top, so a
        // dense grid stays readable where outlines would not.
        (pk.cells || []).forEach(function (s) {
          if (!s || s.k < 0 || s.k >= geo.n || s.c < 0 || s.c >= geo.cols || !geo.ridges[s.k]) return;
          var h = Math.max(2, geo.ridges[s.k][s.c] * geo.RH);
          g.fillStyle = pk.cellColor || pk.color(s.c);
          g.fillRect(geo.rowOx[s.k] + s.c * cwp + 0.5, geo.rowOy[s.k] - h - 1.5, Math.max(1, cwp - 1), 3);
        });
      }
      cell(o.sel, T.signal, 2);
      var hv = st.hover;
      if (hv && geo.ridges[hv.k]) {
        var ox0 = geo.rowOx[hv.k], oy0 = geo.rowOy[hv.k], x = ox0 + (hv.c + 0.5) * geo.PW / geo.cols;
        g.strokeStyle = T.signal; g.lineWidth = 1;
        g.beginPath(); g.moveTo(x, oy0); g.lineTo(x, oy0 - geo.RH); g.stroke();
        g.beginPath(); g.moveTo(ox0, oy0 + 0.5); g.lineTo(ox0 + geo.PW, oy0 + 0.5); g.stroke();
      }
    };
  }
  // st: the canvas's own {off, dirty, geo, hover, o}; o as above. With
  // no o the picture is kept and only the overlay drawn again.
  function grid(cv, st, o) {
    if (o) { st.o = o; st.dirty = true; }
    if (!st.o) return;
    frame(cv, st, gridRender(st), gridOverlay(st));
  }
  // The cell under a pointer event: {k, c}, or null off the grid.
  function at(cv, st, ev) {
    var geo = st.geo;
    if (!geo) return null;
    var b = cv.getBoundingClientRect(), x = ev.clientX - b.left, y = ev.clientY - b.top;
    var k = hit(geo, x, y);
    if (k < 0) return null;
    var c = colAt(geo, k, x);
    return c < 0 ? null : { k: k, c: c };
  }
  // The tooltip, as Spectrum's: lines of [text, dim], beside the
  // pointer, inside the window; null lines hide it.
  function tip(box, lines, ev) {
    while (box.firstChild) box.removeChild(box.firstChild);
    if (!lines || !lines.length) { box.hidden = true; return; }
    lines.forEach(function (l) {
      var d = document.createElement("div");
      if (l[1]) d.className = "d-dim";
      d.textContent = String(l[0]);
      box.appendChild(d);
    });
    box.hidden = false;
    box.style.left = Math.max(0, Math.min(window.innerWidth - 240, ev.clientX + 12)) + "px";
    box.style.top = Math.max(0, ev.clientY + 12) + "px";
  }

  window.SlothIso = { theme: theme, scheme: scheme, rgbOf: rgbOf, mix: mix, heatRGB: heatRGB, css: css,
                      layout: layout, rails: rails, paint: paint, hit: hit, colAt: colAt,
                      frame: frame, grid: grid, at: at, tip: tip };
})();
