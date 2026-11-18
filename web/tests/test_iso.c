/* #224 (owner 2026-11-16: "Make the WiFi and ble spectrums iso metric
 * like the spectrum tab"): the isometric waterfall as one module,
 * web/ui/iso.js (window.SlothIso), which the Spectrum tab's render()
 * now draws through and the WiFi channel waterfall and the BLE Devices
 * tab's two panels draw with by default, each tab with a flat/iso
 * checkbox kept per viewer. The suite runs no script, so the page is
 * held by its text: the shared projection, painter, hit test,
 * offscreen copy, pointer cell and tooltip pinned whole; Spectrum's
 * draw() pinned whole and its old painter gone from its module; the
 * module before every user of it; the two toggles real checkboxes,
 * checked in the markup, read as isometric unless the viewer kept
 * "flat", and written as no value for the default; the new markup
 * with no inline handler. The behaviour (the Spectrum picture the same
 * pixels before and after, hover, click and the toggles) was driven
 * in headless Chromium against synthetic answers.
 *
 * Each absence assertion here was seen red before it was trusted, and
 * restored byte-identical from a copy: Spectrum's own painter with a
 * stub "function rowAt(x, y) {" put back in spectrum.js; the module's
 * sinks with a comment naming setAttribute added to iso.js; the inline
 * handler scan with onchange="x()" added to the w-iso checkbox; the
 * order with @include iso.js moved after spectrum.js. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "wtest.h"

static const char *page(void) { return (const char *)web_page; }

/* A module's text: from its first line to its namespace's assignment. */
static char *slice(const char *from, const char *to) {
    const char *a = strstr(page(), from);
    const char *b = a ? strstr(a, to) : NULL;
    if (!a || !b) return NULL;
    char *out = malloc((size_t)(b - a) + 1);
    if (!out) return NULL;
    memcpy(out, a, (size_t)(b - a));
    out[b - a] = '\0';
    return out;
}

#define ISO_FROM  "// slothweb: the isometric waterfall (#224"
#define ISO_TO    "  window.SlothIso = {"
#define SPEC_FROM "// slothweb: the Spectrum tab (2026-11-13"
#define SPEC_TO   "  window.SlothSpectrum = {"

static const char LAYOUT[] =
        "  function layout(o) {\n"
        "    var n = o.n, L = o.L, R = o.R, W = o.W, avail = o.Hh - o.top - o.bottom;\n"
        "    var DXT, DYT;\n"
        "    if (o.deep) {\n"
        "      // The depth axis is time, its share of the height growing with\n"
        "      // the rows it holds (3 rows ~30%, 288 ~65%).\n"
        "      var share = Math.min(0.65, 0.3 + 0.07 * Math.log(Math.max(n, 3) / 3) / Math.LN2);\n"
        "      DYT = avail * share; DXT = Math.min((W - L - R) * 0.16, DYT * 0.9);\n"
        "    } else {\n"
        "      // A few rows: the original ridge spacing.\n"
        "      DXT = Math.min(28, (W - L - R) * 0.04) * (n - 1); DYT = Math.min(30, avail * 0.12) * (n - 1);\n"
        "    }\n"
        "    var PW = Math.max(100, W - L - R - DXT), base0 = o.Hh - o.bottom;\n"
        "    var RH = Math.max(40, base0 - o.top - DYT);\n"
        "    return { L: L, PW: PW, DXT: DXT, DYT: DYT, base0: base0, RH: RH, n: n, top: o.top,\n"
        "             rowOx: [], rowOy: [], ridges: [], cols: 0, front: [] };\n"
        "  }";

static const char PAINT[] =
        "  function paint(g, T, geo, o) {\n"
        "    var n = geo.n, cols = o.cols, PW = geo.PW, RH = geo.RH, c, k;\n"
        "    geo.cols = cols;\n"
        "    var order = [];\n"
        "    for (var i = 0; i < n; i++) order.push(i);\n"
        "    order.sort(function (a, b) { return o.depth(b) - o.depth(a); });   // back first\n"
        "    var dense = n > 24, pal = [], cap = [];\n"
        "    for (k = 0; k <= 64; k++) {\n"
        "      pal.push(css(mix(T.bg, heatRGB(T, k / 64), dense ? 0.12 + 0.5 * k / 64 : 0.35 + 0.65 * k / 64)));\n"
        "      cap.push(css(heatRGB(T, k / 64)));\n"
        "    }\n"
        "    var gp = o.gap ? Math.min(o.gap, PW / cols * 0.2) : 0;\n"
        "    var seg = o.segments ? segPainter(g, T, dense) : null, capOf = o.cap ? colorCache(g) : null;\n"
        "    var every = n <= 24 ? 1 : Math.ceil(n / 24);\n"
        "    for (var r = 0; r < n; r++) {\n"
        "      var idx = order[r], d = o.depth(idx), x0 = ox(geo, d), y0 = oy(geo, d), ridge = new Float32Array(cols);\n"
        "      var front = r === n - 1;\n"
        "      for (c = 0; c < cols; c++) {\n"
        "        var f = o.value(idx, c);\n"
        "        f = num(f) ? Math.max(0, Math.min(1, f)) : 0;\n"
        "        ridge[c] = f;\n"
        "        var hpx = f * RH;\n"
        "        if (hpx < 0.5) continue;\n"
        "        var sg = seg ? o.segments(idx, c) : null, cc = capOf ? capOf(o.cap(c)) : null;\n"
        "        if (sg && sg.length) seg(sg, f, x0 + c * PW / cols + gp, y0, PW / cols + 0.6 - 2 * gp, hpx);\n"
        "        else {\n"
        "          g.fillStyle = pal[Math.round(f * 64)];\n"
        "          g.fillRect(x0 + c * PW / cols + gp, y0 - hpx, PW / cols + 0.6 - 2 * gp, hpx);\n"
        "        }\n"
        "        if (cc) { g.fillStyle = cc; g.fillRect(x0 + c * PW / cols + gp, y0 - hpx, PW / cols + 0.6 - 2 * gp, Math.min(dense ? 1.5 : 2, hpx)); }\n"
        "        else if (dense) { g.fillStyle = cap[Math.round(f * 64)]; g.fillRect(x0 + c * PW / cols + gp, y0 - hpx, PW / cols + 0.6 - 2 * gp, Math.min(1.5, hpx)); }\n"
        "      }\n"
        "      geo.rowOx[idx] = x0; geo.rowOy[idx] = y0; geo.ridges[idx] = ridge;\n"
        "      // The baseline under the ridge, so a quiet row still shows.\n"
        "      g.strokeStyle = T.rule; g.lineWidth = 1;\n"
        "      if (n <= 48 || front) { g.beginPath(); g.moveTo(x0, y0 + 0.5); g.lineTo(x0 + PW, y0 + 0.5); g.stroke(); }\n"
        "      if (front || (n - 1 - r) % every === 0) {\n"
        "        g.beginPath();\n"
        "        for (c = 0; c < cols; c++) {\n"
        "          var px = x0 + (c + 0.5) * PW / cols, py = y0 - ridge[c] * RH;\n"
        "          if (o.step) {\n"
        "            // Discrete columns: the outline runs along each column's top.\n"
        "            var sx = x0 + c * PW / cols + gp;\n"
        "            if (c) g.lineTo(sx, py); else g.moveTo(sx, py);\n"
        "            g.lineTo(sx + PW / cols - 2 * gp, py);\n"
        "          } else if (c) g.lineTo(px, py); else g.moveTo(px, py);\n"
        "        }\n"
        "        g.strokeStyle = front ? T.ink : css(heatRGB(T, 0.6), n > 24 ? 0.55 : 0.9);\n"
        "        g.lineWidth = front ? 1 : 0.8;\n"
        "        g.stroke();\n"
        "      }\n"
        "      if (o.after) o.after(idx, x0, y0);\n"
        "    }\n"
        "  }";

static const char HIT[] =
        "  function hit(geo, x, y) {\n"
        "    var best = -1, bestD = Infinity, order = [];\n"
        "    for (var i = 0; i < geo.n; i++) if (geo.ridges[i]) order.push(i);\n"
        "    order.sort(function (a, b) { return geo.rowOy[b] - geo.rowOy[a]; });   // front first\n"
        "    for (var k = 0; k < order.length; k++) {\n"
        "      var idx = order[k], f = (x - geo.rowOx[idx]) / geo.PW;\n"
        "      if (f < 0 || f > 1) continue;\n"
        "      var c = Math.min(geo.cols - 1, Math.floor(f * geo.cols)), oy0 = geo.rowOy[idx];\n"
        "      if (y <= oy0 + 1 && y >= oy0 - Math.max(2, geo.ridges[idx][c] * geo.RH)) return idx;\n"
        "      var dd = Math.abs(y - oy0);\n"
        "      if (dd < bestD) { bestD = dd; best = idx; }\n"
        "    }\n"
        "    return best;\n"
        "  }";

static const char COLAT[] =
        "  function colAt(geo, idx, x) {\n"
        "    var f = (x - geo.rowOx[idx]) / geo.PW;\n"
        "    if (!(f >= 0 && f <= 1)) return -1;\n"
        "    return Math.min(geo.cols - 1, Math.floor(f * geo.cols));\n"
        "  }";

static const char FRAME[] =
        "  function frame(cv, st, render, overlay) {\n"
        "    var dpr = window.devicePixelRatio || 1, W = cv.clientWidth || 800, Hh = cv.clientHeight || 460;\n"
        "    if (cv.width !== Math.round(W * dpr) || cv.height !== Math.round(Hh * dpr)) {\n"
        "      cv.width = Math.round(W * dpr); cv.height = Math.round(Hh * dpr);\n"
        "      st.dirty = true;\n"
        "    }\n"
        "    if (!st.off) st.off = document.createElement(\"canvas\");\n"
        "    if (st.dirty || st.off.width !== cv.width || st.off.height !== cv.height) {\n"
        "      st.off.width = cv.width; st.off.height = cv.height;\n"
        "      render(st.off, dpr, W, Hh);\n"
        "      st.dirty = false;\n"
        "    }\n"
        "    var g = cv.getContext(\"2d\");\n"
        "    g.setTransform(1, 0, 0, 1, 0, 0);\n"
        "    g.clearRect(0, 0, cv.width, cv.height);\n"
        "    g.drawImage(st.off, 0, 0);\n"
        "    g.setTransform(dpr, 0, 0, dpr, 0, 0);\n"
        "    if (overlay) overlay(g);\n"
        "  }";

static const char AT[] =
        "  function at(cv, st, ev) {\n"
        "    var geo = st.geo;\n"
        "    if (!geo) return null;\n"
        "    var b = cv.getBoundingClientRect(), x = ev.clientX - b.left, y = ev.clientY - b.top;\n"
        "    var k = hit(geo, x, y);\n"
        "    if (k < 0) return null;\n"
        "    var c = colAt(geo, k, x);\n"
        "    return c < 0 ? null : { k: k, c: c };\n"
        "  }";

static const char TIP[] =
        "  function tip(box, lines, ev) {\n"
        "    while (box.firstChild) box.removeChild(box.firstChild);\n"
        "    if (!lines || !lines.length) { box.hidden = true; return; }\n"
        "    lines.forEach(function (l) {\n"
        "      var d = document.createElement(\"div\");\n"
        "      if (l[1]) d.className = \"d-dim\";\n"
        "      d.textContent = String(l[0]);\n"
        "      box.appendChild(d);\n"
        "    });\n"
        "    box.hidden = false;\n"
        "    box.style.left = Math.max(0, Math.min(window.innerWidth - 240, ev.clientX + 12)) + \"px\";\n"
        "    box.style.top = Math.max(0, ev.clientY + 12) + \"px\";\n"
        "  }";

static const char SPEC_DRAW[] =
        "  function draw() {\n"
        "    var cv = $(\"spec-plot\");\n"
        "    if (!cv) return;\n"
        "    ISO.frame(cv, fr, render, function (g) {\n"
        "      if (!geo) return;\n"
        "      var T = theme(g);\n"
        "      if (drag && drag.x1 !== undefined) {\n"
        "        g.fillStyle = css(rgbOf(g, T.signal), 0.15);\n"
        "        g.fillRect(Math.min(drag.x0, drag.x1), geo.top - 10, Math.abs(drag.x1 - drag.x0), geo.base0 - geo.top + 10);\n"
        "      }\n"
        "      if (hover) {\n"
        "        g.strokeStyle = T.signal; g.lineWidth = 1;\n"
        "        g.beginPath(); g.moveTo(hover.x, hover.oy); g.lineTo(hover.x, hover.oy - geo.RH); g.stroke();\n"
        "        g.beginPath(); g.moveTo(hover.ox, hover.oy + 0.5); g.lineTo(hover.ox + geo.PW, hover.oy + 0.5); g.stroke();\n"
        "      }\n"
        "    });\n"
        "  }";

static const char CHANNEL_GRID[] =
        "  function channelGrid() {\n"
        "    var iso = WF.iso, hz = $(\"w-grid\").value !== \"mix\";\n"
        "    $(\"w-grid\").disabled = iso;\n"
        "    $(\"w-g3wrap\").classList.toggle(\"mix\", iso || !hz);\n"
        "    $(\"w-heat\").classList.toggle(\"iso\", iso);\n"
        "    $(\"w-heat\").ariaLabel = iso ? W_ISO_LABEL : W_FLAT_LABEL;\n"
        "    $(\"w-drill\").hidden = iso || !hz;\n"
        "    $(\"w-hz-sub\").hidden = iso || !hz;\n"
        "    $(\"w-mx-sub\").hidden = iso || hz;\n"
        "    $(\"w-iso-sub\").hidden = !iso;\n"
        "    $(\"w-iso-key\").hidden = !iso;\n"
        "    if (!iso) { WF.ist.hover = null; $(\"w-iso-tip\").hidden = true; }\n"
        "    if (iso) { isoGrid(); return; }\n"
        "    if (hz) horizonGrid(); else mixGrid();\n"
        "  }";

static const char ISO_PICK[] =
        "  function isoPick(ev) {\n"
        "    var at = SlothIso.at($(\"w-heat\"), WF.ist, ev);\n"
        "    if (!at || at.c >= WF.rows.length) return;\n"
        "    if (WF.cur && WF.cur.r === at.c && WF.cur.c === at.k) return;\n"
        "    WF.cur = { r: at.c, c: at.k };\n"
        "    channelGrid();\n"
        "  }";

static const char BLE_ISO_MODE[] =
        "  function isoMode() {\n"
        "    [\"bledev-classes\", \"bledev-prox\"].forEach(function (id) {\n"
        "      var c = $(id);\n"
        "      if (!Object.prototype.hasOwnProperty.call(FLAT_LABEL, id)) FLAT_LABEL[id] = c.ariaLabel;\n"
        "      c.ariaLabel = S.iso ? ISO_LABEL[id] : FLAT_LABEL[id];\n"
        "      c.classList.toggle(\"iso\", S.iso);\n"
        "    });\n"
        "    $(\"bledev-iso-sub\").hidden = !S.iso;\n"
        "    $(\"bledev-cls-key\").hidden = $(\"bledev-prox-key\").hidden = !S.iso || noSensor();\n"
        "    if (!S.iso) { S.ist.hover = S.pist.hover = null; $(\"bledev-iso-tip\").hidden = true; }\n"
        "  }";

static const char BLE_ISO_PICK[] =
        "  function isoPick(ev, which) {\n"
        "    var p = which === \"p\", at = SlothIso.at($(p ? \"bledev-prox\" : \"bledev-classes\"), p ? S.pist : S.ist, ev);\n"
        "    var key = p ? \"pcur\" : \"cur\";\n"
        "    if (!at || at.c >= (p ? S.prows : S.rows).length) return;\n"
        "    if (S[key] && S[key].r === at.c && S[key].c === at.k) return;\n"
        "    S[key] = { r: at.c, c: at.k };\n"
        "    if (p) proxGrid(); else classGrid();\n"
        "  }";

static const char RAILS[] =
        "  function rails(g, T, geo) {\n"
        "    var L = geo.L, PW = geo.PW, base0 = geo.base0;\n"
        "    g.strokeStyle = T.rule; g.lineWidth = 1;\n"
        "    g.beginPath(); g.moveTo(L, base0); g.lineTo(L + geo.DXT, base0 - geo.DYT);\n"
        "    g.moveTo(L + PW, base0); g.lineTo(L + PW + geo.DXT, base0 - geo.DYT); g.stroke();\n"
        "  }";

static const char GRID_RENDER[] =
        "  function gridRender(st) {\n"
        "    return function (cv, dpr, W, Hh) {\n"
        "      var o = st.o, g = cv.getContext(\"2d\");\n"
        "      g.setTransform(dpr, 0, 0, dpr, 0, 0);\n"
        "      var T = theme(g);\n"
        "      g.clearRect(0, 0, W, Hh);\n"
        "      g.font = \"10px \" + cssVar(\"--font-mono\", \"monospace\");\n"
        "      st.geo = null;\n"
        "      var nc = o.cols.length, n = o.n;\n"
        "      if (!nc || !n) {\n"
        "        g.fillStyle = T.muted;\n"
        "        g.fillText(o.empty || \"no data\", 16, 24);\n"
        "        return;\n"
        "      }\n"
        "      var grouped = o.cols.some(function (c) { return !!c.group; });\n"
        "      var floored = o.cols.some(function (c) { return !!c.floor; }), fy = floored ? 7 : 0;\n"
        "      var lane = o.lane || null, ly = lane ? 14 : 0;\n"
        "      var geo = layout({ W: W, Hh: Hh, n: n, L: 44, R: 56, top: 14, bottom: (grouped ? 34 : 22) + fy + ly, deep: n > 12 });\n"
        "      geo.foot = 17 + fy + ly;\n"
        "      st.geo = geo;\n"
        "      // A scale with no extent (a caller's hi equal to its lo) is one\n"
        "      // unit wide, so no tick, height or ridge is NaN.\n"
        "      var span = o.hi > o.lo ? o.hi - o.lo : 1, PW = geo.PW, base0 = geo.base0, RH = geo.RH, k;\n"
        "      rails(g, T, geo);\n"
        "      // The level scale at left.\n"
        "      g.fillStyle = T.muted; g.strokeStyle = T.rule; g.textAlign = \"right\";\n"
        "      var tk = o.ticks || [o.lo, (o.lo + o.hi) / 2, o.hi];\n"
        "      for (k = 0; k < tk.length; k++) {\n"
        "        var yy = base0 - (tk[k] - o.lo) / span * RH;\n"
        "        g.fillText(o.fmt ? o.fmt(tk[k]) : String(tk[k]), geo.L - 4, yy + 3);\n"
        "        g.beginPath(); g.moveTo(geo.L - 2, yy); g.lineTo(geo.L, yy); g.stroke();\n"
        "      }\n"
        "      if (o.unit) {\n"
        "        g.save(); g.translate(8, base0 - RH / 2); g.rotate(-Math.PI / 2); g.textAlign = \"center\";\n"
        "        g.fillText(o.unit, 0, 0); g.restore();\n"
        "      }\n"
        "      function depth(i) { return n > 1 ? (n - 1 - i) / (n - 1) : 0; }\n"
        "      paint(g, T, geo, {\n"
        "        cols: nc, depth: depth, gap: 1, step: true,\n"
        "        value: function (i, c) {\n"
        "          var v = o.value(i, c);\n"
        "          return num(v) && span > 0 ? (v - o.lo) / span : 0;\n"
        "        },\n"
        "        segments: o.segments, cap: o.cols.some(function (c) { return !!c.cap; }) ? function (c) { return o.cols[c].cap; } : null,\n"
        "        after: lane && lane.foot ? function (i, x0, y0) {\n"
        "          // Drawn as each row goes down, so a nearer row hides it.\n"
        "          for (var fc = 0; fc < nc; fc++) {\n"
        "            var fcol = lane.foot(i, fc);\n"
        "            if (!fcol) continue;\n"
        "            g.fillStyle = fcol;\n"
        "            g.fillRect(x0 + (fc + 0.25) * PW / nc, y0 + 1, Math.max(1, PW / nc * 0.5), 2);\n"
        "          }\n"
        "        } : null\n"
        "      });\n"
        "      // The time axis up the right rail: a label a label height apart.\n"
        "      g.fillStyle = T.muted; g.strokeStyle = T.rule; g.textAlign = \"left\";\n"
        "      var every = Math.max(1, Math.ceil(16 / Math.max(0.01, geo.DYT / Math.max(1, n - 1))));\n"
        "      for (k = n - 1; k >= 0; k -= every) {\n"
        "        var d = depth(k), x = ox(geo, d) + PW, y = oy(geo, d);\n"
        "        g.beginPath(); g.moveTo(x + 2, y); g.lineTo(x + 6, y); g.stroke();\n"
        "        g.fillText(o.clock(o.from + k * o.col_s), x + 8, y + 3);\n"
        "      }\n"
        "      // The columns' names under the front row, a name where it fits,\n"
        "      // then each group's name under its span.\n"
        "      g.textAlign = \"center\";\n"
        "      var cw = PW / nc, last = -Infinity, gs = 0;\n"
        "      // The floor strip under the names: each column's colour across\n"
        "      // its width, dashed where the caller marks it (DFS).\n"
        "      for (var fc = 0; floored && fc < nc; fc++) {\n"
        "        var fl = o.cols[fc].floor;\n"
        "        if (!fl) continue;\n"
        "        g.fillStyle = fl.color;\n"
        "        var fx = geo.L + fc * cw + 0.5, fz = geo.L + (fc + 1) * cw - 0.5;\n"
        "        if (!fl.dash) { g.fillRect(fx, base0 + 15, Math.max(0.5, fz - fx), 4); continue; }\n"
        "        for (var dx = fx; dx < fz; dx += 5) g.fillRect(dx, base0 + 15, Math.min(3, fz - dx), 4);\n"
        "      }\n"
        "      if (lane) {\n"
        "        var lcy = base0 + 19 + fy, lmax = 0, lc;\n"
        "        for (lc = 0; lc < nc; lc++) lmax = Math.max(lmax, num(lane.count(lc)) ? lane.count(lc) : 0);\n"
        "        // At the left edge: the level axis's labels sit above it.\n"
        "        g.fillStyle = T.muted; g.textAlign = \"left\";\n"
        "        g.fillText(lane.name, 1, lcy + 3);\n"
        "        g.textAlign = \"left\";\n"
        "        for (lc = 0; lc < nc; lc++) {\n"
        "          var ln = lane.count(lc);\n"
        "          if (!num(ln) || ln <= 0) continue;\n"
        "          var lt = String(ln), ltw = g.measureText(lt).width, rr = Math.min(cw * 0.45, 2 + 3 * Math.sqrt(ln / lmax));\n"
        "          var lx = geo.L + (lc + 0.5) * cw, wide = cw >= ltw + 2 * rr + 4;\n"
        "          if (wide) lx -= (ltw + 2) / 2;\n"
        "          g.fillStyle = lane.color(lc);\n"
        "          g.beginPath(); g.moveTo(lx, lcy - rr); g.lineTo(lx + rr, lcy); g.lineTo(lx, lcy + rr); g.lineTo(lx - rr, lcy);\n"
        "          g.closePath(); g.fill();\n"
        "          if (wide) { g.fillStyle = T.ink; g.fillText(lt, lx + rr + 2, lcy + 3); }\n"
        "        }\n"
        "        g.textAlign = \"center\";\n"
        "      }\n"
        "      for (var c = 0; c <= nc; c++) {\n"
        "        if (c < nc) {\n"
        "          var cx = geo.L + (c + 0.5) * cw, lab = o.cols[c].label, w = g.measureText(lab).width;\n"
        "          if (w > cw - 2 && o.cols[c].short) { lab = o.cols[c].short; w = g.measureText(lab).width; }\n"
        "          if (cx - w / 2 > last + 3) {\n"
        "            g.fillStyle = T.muted;\n"
        "            g.fillText(lab, cx, base0 + 12);\n"
        "            last = cx + w / 2;\n"
        "          }\n"
        "        }\n"
        "        if (grouped && (c === nc || (c > gs && o.cols[c].group !== o.cols[gs].group))) {\n"
        "          var a = geo.L + gs * cw, z = geo.L + c * cw;\n"
        "          g.strokeStyle = T.rule;\n"
        "          g.beginPath(); g.moveTo(a + 2, base0 + 18.5 + fy + ly); g.lineTo(z - 2, base0 + 18.5 + fy + ly); g.stroke();\n"
        "          var gl = o.cols[gs].group || \"\";\n"
        "          if (gl && g.measureText(gl).width >= z - a && o.cols[gs].groupShort) gl = o.cols[gs].groupShort;\n"
        "          if (gl && g.measureText(gl).width < z - a) { g.fillStyle = o.cols[gs].groupColor || T.ink; g.fillText(gl, (a + z) / 2, base0 + 29 + fy + ly); }\n"
        "          gs = c;\n"
        "        }\n"
        "      }\n"
        "      g.textAlign = \"left\";\n"
        "    };\n"
        "  }";

static const char GRID_OVERLAY[] =
        "  function gridOverlay(st) {\n"
        "    return function (g) {\n"
        "      var geo = st.geo, o = st.o;\n"
        "      if (!geo) return;\n"
        "      var T = theme(g);\n"
        "      function cell(s, color, w) {\n"
        "        if (!s || s.k < 0 || s.k >= geo.n || s.c < 0 || s.c >= geo.cols || !geo.ridges[s.k]) return;\n"
        "        var x0 = geo.rowOx[s.k], y0 = geo.rowOy[s.k], cw = geo.PW / geo.cols;\n"
        "        var h = Math.max(2, geo.ridges[s.k][s.c] * geo.RH);\n"
        "        g.strokeStyle = color; g.lineWidth = w;\n"
        "        g.strokeRect(x0 + s.c * cw + 0.5, y0 - h + 0.5, Math.max(1, cw - 1), h);\n"
        "      }\n"
        "      var pk = o.pick, fk = geo.n - 1, cwp = geo.PW / geo.cols;\n"
        "      if (pk && geo.ridges[fk] && geo.ridges[0]) {\n"
        "        (pk.cols || []).forEach(function (c) {\n"
        "          if (!(c >= 0 && c < geo.cols)) return;\n"
        "          // The column's floor from the newest row to the oldest, and its\n"
        "          // slot under the front row down through the lane.\n"
        "          g.strokeStyle = pk.color(c); g.lineWidth = 3;\n"
        "          g.beginPath(); g.moveTo(geo.rowOx[fk] + (c + 0.5) * cwp, geo.rowOy[fk] + 2);\n"
        "          g.lineTo(geo.rowOx[0] + (c + 0.5) * cwp, geo.rowOy[0] + 2); g.stroke();\n"
        "          g.lineWidth = 2;\n"
        "          g.strokeRect(geo.L + c * cwp + 1, geo.base0 + 2, Math.max(1, cwp - 2), geo.foot || 17);\n"
        "        });\n"
        "        // A cell it was named in: a bar across its column's top, so a\n"
        "        // dense grid stays readable where outlines would not.\n"
        "        (pk.cells || []).forEach(function (s) {\n"
        "          if (!s || s.k < 0 || s.k >= geo.n || s.c < 0 || s.c >= geo.cols || !geo.ridges[s.k]) return;\n"
        "          var h = Math.max(2, geo.ridges[s.k][s.c] * geo.RH);\n"
        "          g.fillStyle = pk.cellColor || pk.color(s.c);\n"
        "          g.fillRect(geo.rowOx[s.k] + s.c * cwp + 0.5, geo.rowOy[s.k] - h - 1.5, Math.max(1, cwp - 1), 3);\n"
        "        });\n"
        "      }\n"
        "      cell(o.sel, T.signal, 2);\n"
        "      var hv = st.hover;\n"
        "      if (hv && geo.ridges[hv.k]) {\n"
        "        var ox0 = geo.rowOx[hv.k], oy0 = geo.rowOy[hv.k], x = ox0 + (hv.c + 0.5) * geo.PW / geo.cols;\n"
        "        g.strokeStyle = T.signal; g.lineWidth = 1;\n"
        "        g.beginPath(); g.moveTo(x, oy0); g.lineTo(x, oy0 - geo.RH); g.stroke();\n"
        "        g.beginPath(); g.moveTo(ox0, oy0 + 0.5); g.lineTo(ox0 + geo.PW, oy0 + 0.5); g.stroke();\n"
        "      }\n"
        "    };\n"
        "  }";

static const char GRID[] =
        "  function grid(cv, st, o) {\n"
        "    if (o) { st.o = o; st.dirty = true; }\n"
        "    if (!st.o) return;\n"
        "    frame(cv, st, gridRender(st), gridOverlay(st));\n"
        "  }";

static const char W_ISO_GRID[] =
        "  function isoGrid() {\n"
        "    var c = $(\"w-heat\");\n"
        "    c.style.height = \"380px\";\n"
        "    var rows = gridRows(), hz = WF.heat;\n"
        "    WF.rows = rows;\n"
        "    var cols = hz && num(hz.cols) ? hz.cols : 0, hmax = 0;\n"
        "    rows.forEach(function (r) {\n"
        "      ((r.heat && r.heat.cells) || []).forEach(function (v) { if (num(v) && v > hmax) hmax = v; });\n"
        "    });\n"
        "    WF.geo = cols && rows.length ? { cols: cols, col_s: hz.col_s, from: hz.from, iso: true } : null;\n"
        "    var unit = hz && hz.metric === \"wifi.ctrl_total\" ? \"control frames\" : \"APs\";\n"
        "    if (hz) set(\"w-heat-note\", rows.length + \" channels, \" + hz.tier + \" tier, \" + fmt(hz.col_s) + \" s cells, \" +\n"
        "                unit + \" 0 to \" + fmt(hmax) + \" (the window's largest cell)\" + (hz.more ? \", more channels than shown\" : \"\"));\n"
        "    mixNote();\n"
        "    var cur = WF.cur, P = SlothIso.scheme(), hl = isoKey(), pc = isoClient();\n"
        "    // The mix's cells line up with the heat's only on the same grid.\n"
        "    var mx = !!(hz && WF.mix && WF.mix.from === hz.from && WF.mix.cols === hz.cols && WF.mix.col_s === hz.col_s);\n"
        "    var sh = rows.map(function (r) { return chanShade(r.band, r.key); });\n"
        "    // Each channel its colour in every list (SlothChan); a band's name\n"
        "    // in its first channel's.\n"
        "    var rc = rows.map(function (r) { return SlothChan.rgb(r.key, r.band); }), gc = {};\n"
        "    rows.forEach(function (r, i) { if (!(r.band in gc)) gc[r.band] = rc[i]; });\n"
        "    var lane = mx ? clientLane(rows) : null, pick = mx && pc ? clientPick(pc, rows, cols, rc) : null;\n"
        "    SlothIso.grid(c, WF.ist, {\n"
        "      cols: rows.map(function (r, i) {\n"
        "        return { label: r.key, short: r.key.replace(/^6g/, \"\"), group: BAND_WORD[r.band] || \"band unknown\",\n"
        "                 groupColor: sh[i] ? gc[r.band] : P.muted,\n"
        "                 floor: { color: rc[i], dash: !!(sh[i] && sh[i].dfs) }, cap: rc[i] };\n"
        "      }),\n"
        "      n: rows.length ? cols : 0, from: hz ? hz.from : 0, col_s: hz ? hz.col_s : 0,\n"
        "      value: function (k, i) { var cl = rows[i].heat && rows[i].heat.cells; return cl ? cl[k] : null; },\n"
        "      segments: function (k, i) { return isoSegs(mx ? rows[i] : null, k, rc[i], mx ? hl : null, pick ? pick.lit(k, i) : null); },\n"
        "      lane: lane, pick: pick,\n"
        "      lo: 0, hi: hmax > 0 ? hmax : 1, ticks: hmax > 0 ? [0, hmax / 2, hmax] : [0], unit: unit, fmt: fmt,\n"
        "      clock: hhmmss, sel: cur && cur.r < rows.length && cur.c < cols ? { k: cur.c, c: cur.r } : null,\n"
        "      empty: hz ? \"no channel in the window\" : \"loading\"\n"
        "    });\n"
        "    mixDetail();\n"
        "  }";

static const char BLE_CLASS_ISO[] =
        "  function classIso(rows, cols, col_s, from) {\n"
        "    var hmax = 0;\n"
        "    rows.forEach(function (r) {\n"
        "      ((r.heat && r.heat.cells) || []).forEach(function (v) { if (num(v) && v > hmax) hmax = v; });\n"
        "    });\n"
        "    var cur = S.cur, P = SlothIso.scheme();\n"
        "    SlothIso.grid($(\"bledev-classes\"), S.ist, {\n"
        "      cols: rows.map(function (r) {\n"
        "        var d = classDef(r.key), hue = classHue(r.key, P);\n"
        "        return { label: d.glyph + \" \" + d.label, short: d.glyph, floor: { color: hue }, cap: hue };\n"
        "      }),\n"
        "      n: rows.length ? cols : 0, from: from, col_s: col_s,\n"
        "      value: function (k, i) { var cl = rows[i].heat && rows[i].heat.cells; return cl ? cl[k] : null; },\n"
        "      segments: function (k, i) { return classSegs(rows[i], k, classHue(rows[i].key, P)); },\n"
        "      lo: 0, hi: hmax > 0 ? hmax : 1, ticks: hmax > 0 ? [0, hmax / 2, hmax] : [0], unit: classUnit(), fmt: H.fmt,\n"
        "      clock: H.hhmmss, sel: cur && cur.r < rows.length && cur.c < cols ? { k: cur.c, c: cur.r } : null,\n"
        "      empty: S.cls ? \"no class in the window\" : \"loading\"\n"
        "    });\n"
        "  }";

static const char BLE_PROX_ISO[] =
        "  function proxIso(rows, p) {\n"
        "    var cur = S.pcur, cols = p && p.cols ? p.cols : 0, P = SlothIso.scheme();\n"
        "    var hue = rows.map(function (r) { return classHue(r[\"class\"], P); });\n"
        "    var step = rows.map(function (r) { return ISO_STEP[addrStep(r.addr)]; });\n"
        "    SlothIso.grid($(\"bledev-prox\"), S.pist, {\n"
        "      cols: rows.map(function (r, i) {\n"
        "        var d = classDef(r[\"class\"]);\n"
        "        return { label: r.name !== null ? r.name : shortAddr(r.addr), short: d.glyph,\n"
        "                 group: d.label, groupShort: d.glyph, groupColor: hue[i], floor: { color: hue[i] }, cap: hue[i] };\n"
        "      }),\n"
        "      n: rows.length ? cols : 0, from: p ? p.from : 0, col_s: p ? p.col_s : 0,\n"
        "      value: function (k, i) { return rows[i].cells ? rows[i].cells[k] : null; },\n"
        "      segments: function (k, i) { return [{ f: 1, color: hue[i], alpha: step[i] }]; },\n"
        "      lo: PROX_LO, hi: PROX_HI, ticks: [-100, -80, -60, -40], unit: \"dBm (mean)\",\n"
        "      fmt: function (v) { return String(v); }, clock: H.hhmmss,\n"
        "      sel: cur && cur.r < rows.length && cur.c < cols ? { k: cur.c, c: cur.r } : null,\n"
        "      empty: p ? \"no advertiser heard in the window\" : \"loading\"\n"
        "    });\n"
        "  }";

static const char SCHEME[] =
        "  function scheme() {\n"
        "    return {\n"
        "      cls: { \"b:phone\": cssVar(\"--iso-c-phone\", \"#5b9bff\"), \"b:wear\": cssVar(\"--iso-c-wear\", \"#6fdc6f\"),\n"
        "             \"b:tag\": cssVar(\"--iso-c-tag\", \"#ff6a3d\"), \"b:hid\": cssVar(\"--iso-c-hid\", \"#f2d240\"),\n"
        "             \"b:bcn\": cssVar(\"--iso-c-bcn\", \"#40e0f0\"), \"b:iot\": cssVar(\"--iso-c-iot\", \"#c07cff\"),\n"
        "             \"b:unk\": cssVar(\"--iso-c-unk\", \"#8a8a96\") },\n"
        "      muted: cssVar(\"--muted\", \"#8a82a0\")\n"
        "    };\n"
        "  }";

static const char SEG_PAINTER[] =
        "  function segPainter(g, T, dense) {\n"
        "    var memo = {};\n"
        "    function shade(color, t) {\n"
        "      var q = Math.round(Math.max(0, Math.min(1, t)) * 32), key = color + \"|\" + q;\n"
        "      if (!Object.prototype.hasOwnProperty.call(memo, key)) memo[key] = toward(g, T, color, q / 32);\n"
        "      return memo[key];\n"
        "    }\n"
        "    return function (sg, f, x, y0, w, hpx) {\n"
        "      var body = dense ? 0.5 + 0.4 * f : 0.6 + 0.4 * f, y = y0, left = hpx;\n"
        "      for (var s = 0; s < sg.length && left > 0; s++) {\n"
        "        var h = s === sg.length - 1 ? left : Math.min(left, Math.max(0, num(sg[s].f) ? sg[s].f : 0) * hpx);\n"
        "        if (!(h > 0)) continue;\n"
        "        g.fillStyle = shade(String(sg[s].color), body * (num(sg[s].alpha) ? sg[s].alpha : 1));\n"
        "        g.fillRect(x, y - h, w, h);\n"
        "        y -= h; left -= h;\n"
        "      }\n"
        "    };\n"
        "  }";

static const char COLOR_CACHE[] =
        "  function colorCache(g) {\n"
        "    var memo = {};\n"
        "    return function (c) {\n"
        "      if (!c) return null;\n"
        "      if (!Object.prototype.hasOwnProperty.call(memo, c)) memo[c] = css(rgbOf(g, c));\n"
        "      return memo[c];\n"
        "    };\n"
        "  }";

static const char CHAN_SHADE[] =
        "  var CHAN_STEP = { \"2.4\": [\"1/6/11\", \"overlapping\"], \"5\": [\"UNII-1\", \"UNII-2A DFS\", \"UNII-2C DFS\", \"UNII-3\", \"other\"],\n"
        "                    \"6\": [\"PSC\", \"non-PSC\"] };\n"
        "  function chanShade(band, key) {\n"
        "    var ch = chanNum(key);\n"
        "    if (band === \"2.4\") return { band: \"2.4\", step: ch === 1 || ch === 6 || ch === 11 ? 0 : 1, dfs: false };\n"
        "    if (band === \"5\") {\n"
        "      var st = ch <= 48 ? 0 : ch <= 64 ? 1 : ch < 100 ? 4 : ch <= 144 ? 2 : ch <= 165 ? 3 : 4;\n"
        "      return { band: \"5\", step: st, dfs: st === 1 || st === 2 };\n"
        "    }\n"
        "    if (band === \"6\") return { band: \"6\", step: ch % 16 === 5 ? 0 : 1, dfs: false };\n"
        "    return null;\n"
        "  }\n"
        "  function chanWord(sc) { return sc ? CHAN_STEP[sc.band][sc.step] : \"band unknown\"; }";

static const char W_ISO_SEGS[] =
        "  function isoSegs(r, k, base, hl, lit) {\n"
        "    var m = r && r.mix && r.mix.cells ? r.mix.cells[k] : null, off = lit === false;\n"
        "    var rest = hl === null && !off ? 1 : ISO_FADE, out = [];\n"
        "    if (!Array.isArray(m) || !num(m[0]) || m[0] <= 0) return [{ f: 1, color: base, alpha: rest }];\n"
        "    for (var e = 2; e + 1 < m.length; e += 2) {\n"
        "      var t = txOf(m[e]);\n"
        "      out.push({ f: m[e + 1] / m[0], color: txColor(t), alpha: !off && (hl === null || ssidOf(t) === hl) ? 1 : ISO_FADE });\n"
        "    }\n"
        "    if (num(m[1]) && m[1] > 0) out.push({ f: m[1] / m[0], color: base, alpha: rest });\n"
        "    return out.length ? out : [{ f: 1, color: base, alpha: rest }];\n"
        "  }";

static const char W_ISO_KEY[] =
        "  function isoKey() {\n"
        "    var box = $(\"w-iso-key\");\n"
        "    while (box.firstChild) box.removeChild(box.firstChild);\n"
        "    [\"2.4\", \"5\", \"6\"].forEach(function (b) {\n"
        "      var grp = box.appendChild(el(\"span\", \"grp\"));\n"
        "      grp.appendChild(el(\"span\", \"nm\", BAND_WORD[b]));\n"
        "      CHAN_STEP[b].forEach(function (w, i) {\n"
        "        var it = grp.appendChild(el(\"span\", \"it\"));\n"
        "        if (b === \"5\" && (i === 1 || i === 2)) it.appendChild(el(\"span\", \"sw dfs\"));\n"
        "        it.appendChild(el(\"span\", \"\", w));\n"
        "        WF.rows.forEach(function (r) {\n"
        "          var sc = r.band === b ? chanShade(r.band, r.key) : null;\n"
        "          if (sc && sc.step === i) it.appendChild(SlothChan.chip(r.key, r.band, r.key.replace(/^6g/, \"\")));\n"
        "        });\n"
        "      });\n"
        "    });\n"
        "    var by = new Map();\n"
        "    ((WF.mix && WF.mix.channels) || []).forEach(function (r) {\n"
        "      (r.cells || []).forEach(function (m) {\n"
        "        if (!Array.isArray(m)) return;\n"
        "        for (var e = 2; e + 1 < m.length; e += 2) {\n"
        "          var t = txOf(m[e]), s = ssidOf(t);\n"
        "          if (s === null || !num(m[e + 1])) continue;\n"
        "          var o = by.get(s);\n"
        "          if (!o) { o = { ssid: s, n: 0, t: t }; by.set(s, o); }\n"
        "          o.n += m[e + 1];\n"
        "        }\n"
        "      });\n"
        "    });\n"
        "    // Only a loaded mix can say the SSID left: a reload clears WF.mix\n"
        "    // and the heat can land first.\n"
        "    if (WF.hl !== null && WF.mix && !by.has(WF.hl)) WF.hl = null;\n"
        "    var list = Array.from(by.values()).sort(function (a, b) { return b.n - a.n || (a.ssid < b.ssid ? -1 : a.ssid > b.ssid ? 1 : 0); });\n"
        "    if (list.length) {\n"
        "      var grp = box.appendChild(el(\"span\", \"grp\"));\n"
        "      grp.appendChild(el(\"span\", \"nm\", \"SSIDs\"));\n"
        "      list.slice(0, ISO_SSIDS).forEach(function (o, i) {\n"
        "        var b = grp.appendChild(el(\"button\", \"chip\"));\n"
        "        b.type = \"button\";\n"
        "        b.ariaPressed = WF.hl === o.ssid ? \"true\" : \"false\";\n"
        "        b.title = WF.hl === o.ssid ? \"show every SSID again\" : \"fade every other SSID\";\n"
        "        var sw = el(\"span\", \"sw\");\n"
        "        sw.style.backgroundColor = txColor(o.t);\n"
        "        b.appendChild(sw);\n"
        "        // the swatch the stacks' colour it keys; the name its channel's\n"
        "        // (SlothChan.mark(): the SSID's most recently heard AP's)\n"
        "        b.appendChild(o.ssid === \"\" ? el(\"span\", \"\", \"(hidden)\") : SlothChan.mark(el(\"span\", \"\", o.ssid), \"ssid\", o.ssid));\n"
        "        b.addEventListener(\"click\", function () {\n"
        "          WF.hl = WF.hl === o.ssid ? null : o.ssid;\n"
        "          // One highlight at a time: an SSID drops a picked client.\n"
        "          if (WF.hl !== null) WF.pc = null;\n"
        "          channelGrid();\n"
        "          // The key is drawn anew: the focus back on the same chip.\n"
        "          var again = $(\"w-iso-key\").querySelectorAll(\"button.chip\")[i];\n"
        "          if (again) again.focus();\n"
        "        });\n"
        "      });\n"
        "      if (list.length > ISO_SSIDS) grp.appendChild(el(\"span\", \"more\", \"+\" + (list.length - ISO_SSIDS) + \" more\"));\n"
        "    }\n"
        "    clientKey(box);\n"
        "    return WF.hl;\n"
        "  }";

/* The client lane (owner 2026-11-17: "the spectrum should show where the
 * clients sit in the spectrum highlighting their channel"), whole: the
 * list read from the mix answer's "clients", a client's colour its AP's
 * SSID's (else its MAC's), its words, its cells from the hex, the lane,
 * the pick and the key's Clients group; and the tooltip's line. */
static const char W_ISO_CLIENTS[] =
        "  // ── the client lane (owner 2026-11-17: \"the spectrum should show where\n"
        "  // the clients sit in the spectrum highlighting their channel\") ──\n"
        "  // The mix's \"clients\" (web_wifi.h): every client the window named,\n"
        "  // busiest first, each with its channels (frames and the cells it was\n"
        "  // named in, as hex) and its AP where sloth.db or the stream paired\n"
        "  // them. A client is named only in a bucket where it was one of the five\n"
        "  // busiest, so a count is a floor and a quiet client may be missing.\n"
        "  // Its colour is its AP's SSID's, so a network's clients group with its\n"
        "  // APs; with no AP known, its MAC's, as txColor() colours a client.\n"
        "  var ISO_CLIENTS = 12;\n"
        "  function clientsOf() {\n"
        "    var l = WF.mix && Array.isArray(WF.mix.clients) ? WF.mix.clients : [];\n"
        "    return l.filter(function (c) { return c && typeof c.id === \"string\" && Array.isArray(c.chans); });\n"
        "  }\n"
        "  function clientColor(c) {\n"
        "    var a = c.assoc, T = theme();\n"
        "    if (a && typeof a.ssid === \"string\" && num(a.ssid_k) && a.ssid_k >= 0 && a.ssid_k < 8) return T.k[a.ssid_k];\n"
        "    return keyColor(c.id);\n"
        "  }\n"
        "  // A client in words: its vendor and the MAC's last three octets,\n"
        "  // \"randomised\" for a locally administered MAC, and its AP's SSID.\n"
        "  function clientName(c) {\n"
        "    var s = (typeof c.vendor === \"string\" && c.vendor ? c.vendor + \" \" : \"\") + String(c.id).slice(-8);\n"
        "    if (c.laa) s += \" randomised\";\n"
        "    if (c.assoc && typeof c.assoc.ssid === \"string\") s += \" \\u2192 \" + (c.assoc.ssid === \"\" ? \"(hidden)\" : c.assoc.ssid);\n"
        "    else if (c.assoc && typeof c.assoc.bssid === \"string\") s += \" \\u2192 \" + c.assoc.bssid;\n"
        "    return s;\n"
        "  }\n"
        "  // Its entry for a channel key ([key, frames, hex]), or null; whether\n"
        "  // the hex names cell k (a digit four cells, the first the high bit).\n"
        "  function clientChan(c, key) {\n"
        "    for (var i = 0; i < c.chans.length; i++) if (Array.isArray(c.chans[i]) && c.chans[i][0] === key) return c.chans[i];\n"
        "    return null;\n"
        "  }\n"
        "  function clientIn(ch, k) {\n"
        "    var d = ch && typeof ch[2] === \"string\" ? parseInt(ch[2].charAt(k >> 2), 16) : NaN;\n"
        "    return num(d) && (d & (8 >> (k & 3))) !== 0;\n"
        "  }\n"
        "  // The picked client, dropped once a loaded mix no longer names it.\n"
        "  function isoClient() {\n"
        "    if (WF.pc === null) return null;\n"
        "    var c = clientsOf().find(function (x) { return x.id === WF.pc; }) || null;\n"
        "    if (!c && WF.mix) WF.pc = null;\n"
        "    return c;\n"
        "  }\n"
        "  // The lane under the floor strip: per channel, the clients the list\n"
        "  // names on it (the busiest one's colour), and a tick at the foot of\n"
        "  // each cell the row's \"clients\" says held one.\n"
        "  function clientLane(rows) {\n"
        "    var cls = clientsOf(), per = rows.map(function (r) {\n"
        "      var n = 0, first = null;\n"
        "      cls.forEach(function (c) { if (clientChan(c, r.key)) { n++; if (!first) first = c; } });\n"
        "      return { n: n, color: first ? clientColor(first) : null };\n"
        "    });\n"
        "    return {\n"
        "      name: \"clients\", count: function (i) { return per[i].n; },\n"
        "      color: function (i) { return per[i].color || theme().muted; },\n"
        "      foot: function (k, i) {\n"
        "        var cl = rows[i].mix && Array.isArray(rows[i].mix.clients) ? rows[i].mix.clients[k] : null;\n"
        "        return num(cl) && cl > 0 ? per[i].color || theme().muted : null;\n"
        "      }\n"
        "    };\n"
        "  }\n"
        "  // The pick: the client's channels traced in their own colours (rc,\n"
        "  // SlothChan's), the cells it was named in outlined in the client's;\n"
        "  // lit(k, i) for isoSegs().\n"
        "  function clientPick(c, rows, cols, rc) {\n"
        "    var on = rows.map(function (r) { return clientChan(c, r.key); }), cells = [], col = clientColor(c);\n"
        "    on.forEach(function (ch, i) {\n"
        "      for (var k = 0; ch && k < cols; k++) if (clientIn(ch, k)) cells.push({ k: k, c: i });\n"
        "    });\n"
        "    return {\n"
        "      cols: on.map(function (ch, i) { return ch ? i : -1; }).filter(function (i) { return i >= 0; }),\n"
        "      color: function (i) { return rc[i]; },\n"
        "      cells: cells, cellColor: col,\n"
        "      lit: function (k, i) { return clientIn(on[i], k); }\n"
        "    };\n"
        "  }\n"
        "  // The key's Clients group: the busiest ISO_CLIENTS, each a button that\n"
        "  // traces its channels and fades every cell it was not named in, until\n"
        "  // pressed again; a client and an SSID are not highlighted together.\n"
        "  function clientKey(box) {\n"
        "    var cls = clientsOf(), mx = WF.mix;\n"
        "    if (!mx || !Array.isArray(mx.clients)) return;\n"
        "    var grp = box.appendChild(el(\"span\", \"grp\"));\n"
        "    grp.appendChild(el(\"span\", \"nm\", \"Clients\"));\n"
        "    if (!cls.length) { grp.appendChild(el(\"span\", \"more\", \"none named in the window\")); return; }\n"
        "    // A picked client the busiest no longer include keeps its chip, so\n"
        "    // the pick can always be undone where it was made.\n"
        "    var shown = cls.slice(0, ISO_CLIENTS);\n"
        "    if (WF.pc !== null && !shown.some(function (c) { return c.id === WF.pc; }))\n"
        "      shown = shown.concat(cls.filter(function (c) { return c.id === WF.pc; }));\n"
        "    shown.forEach(function (c, i) {\n"
        "      var on = WF.pc === c.id, b = grp.appendChild(el(\"button\", \"chip cl\"));\n"
        "      b.type = \"button\";\n"
        "      b.ariaPressed = on ? \"true\" : \"false\";\n"
        "      b.title = (on ? \"show every cell again\" : \"trace its channels, fade the rest\") + \"; \" +\n"
        "        c.chans.map(function (ch) { return \"ch \" + ch[0] + \" \" + fmt(ch[1]); }).join(\", \") + \" frames\";\n"
        "      var sw = el(\"span\", \"sw dia\");\n"
        "      sw.style.backgroundColor = clientColor(c);\n"
        "      b.appendChild(sw);\n"
        "      // the diamond its network's colour; the name the channel the\n"
        "      // client was last heard on (SlothChan.mark()), else its busiest here\n"
        "      b.appendChild(SlothChan.mark(el(\"span\", \"\", clientName(c)), \"mac\", c.id,\n"
        "                                   c.chans.length && Array.isArray(c.chans[0]) ? c.chans[0][0] : null));\n"
        "      b.addEventListener(\"click\", function () {\n"
        "        WF.pc = on ? null : c.id;\n"
        "        if (WF.pc !== null) WF.hl = null;\n"
        "        channelGrid();\n"
        "        var again = $(\"w-iso-key\").querySelectorAll(\"button.chip.cl\")[i];\n"
        "        if (again) again.focus();\n"
        "      });\n"
        "    });\n"
        "    var total = num(mx.clients_total) ? mx.clients_total : cls.length;\n"
        "    if (total > shown.length)\n"
        "      grp.appendChild(el(\"span\", \"more\", \"+\" + (total - shown.length) + \" more\"));\n"
        "  }";

static const char W_ISO_TIP_CLIENTS[] =
        "  // The tooltip's client line: the clients named in the cell (a floor),\n"
        "  // and with one picked, its frames there.\n"
        "  function isoTipClients(r, k) {\n"
        "    var cl = r.mix && Array.isArray(r.mix.clients) ? r.mix.clients[k] : null, s = \"\";\n"
        "    if (num(cl)) s = cl === 1 ? \"1 client named here\" : fmt(cl) + \" clients named here\";\n"
        "    var c = WF.pc !== null ? clientsOf().find(function (x) { return x.id === WF.pc; }) : null;\n"
        "    if (!c) return s;\n"
        "    var m = r.mix && r.mix.cells ? r.mix.cells[k] : null, f = null;\n"
        "    for (var e = 2; Array.isArray(m) && e + 1 < m.length; e += 2) {\n"
        "      var t = txOf(m[e]);\n"
        "      if (t && t.id === c.id) f = m[e + 1];\n"
        "    }\n"
        "    var w = clientName(c) + \": \" + (num(f) ? fmt(f) + \" frames here\"\n"
        "      : clientIn(clientChan(c, r.key), k) ? \"named here, its frames among the rest\" : \"not named here\");\n"
        "    return s ? s + \"; \" + w : w;\n"
        "  }";

static const char BLE_COLOURS[] =
        "  var ISO_STEP = [1, 0.78, 0.6, 0.45], ISO_REST = 0.32;\n"
        "  function classHue(slug, P) { return P.cls[classDef(slug).slug]; }\n"
        "  function classToken(slug) { return \"var(--iso-c-\" + classDef(slug).slug.slice(2) + \")\"; }\n"
        "  function addrStep(a) {\n"
        "    var h = 0, s = String(a);\n"
        "    for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;\n"
        "    return h % ISO_STEP.length;\n"
        "  }\n"
        "  // The proximity panel's advertisers grouped by class, in CLASSES'\n"
        "  // order, each class keeping the table's order (trackers first, then\n"
        "  // the nearest).\n"
        "  function byClass(rows) {\n"
        "    return rows.map(function (r, i) { return { r: r, i: i, c: CLASS_OF[classDef(r[\"class\"]).slug] }; })\n"
        "      .sort(function (a, b) { return a.c - b.c || a.i - b.i; })\n"
        "      .map(function (e) { return e.r; });\n"
        "  }";

static const char BLE_CLASS_SEGS[] =
        "  function classSegs(r, k, hue) {\n"
        "    var m = r.mix && r.mix.cells ? r.mix.cells[k] : null, out = [];\n"
        "    if (!Array.isArray(m) || !num(m[0]) || m[0] <= 0) return [{ f: 1, color: hue }];\n"
        "    for (var e = 2, s = 0; e + 1 < m.length; e += 2, s++)\n"
        "      out.push({ f: m[e + 1] / m[0], color: hue, alpha: ISO_STEP[Math.min(s, ISO_STEP.length - 1)] });\n"
        "    if (num(m[1]) && m[1] > 0) out.push({ f: m[1] / m[0], color: hue, alpha: ISO_REST });\n"
        "    return out.length ? out : [{ f: 1, color: hue }];\n"
        "  }";

static const char BLE_CLASS_KEY[] =
        "  function classKey(id) {\n"
        "    var box = clear($(id));\n"
        "    CLASSES.forEach(function (c) {\n"
        "      var it = H.el(\"span\", \"it\"), sw = H.el(\"span\", \"sw\");\n"
        "      sw.style.backgroundColor = classToken(c.slug);\n"
        "      it.appendChild(sw);\n"
        "      it.appendChild(H.el(\"span\", \"\", c.glyph + \" \" + c.label));\n"
        "      box.appendChild(it);\n"
        "    });\n"
        "  }";


/* The shared pieces, whole. */
static void test_iso_module_pinned(void) {
    const char *p = page();
    WT_HAS(p, LAYOUT);
    WT_HAS(p, PAINT);
    WT_HAS(p, HIT);
    WT_HAS(p, COLAT);
    WT_HAS(p, FRAME);
    WT_HAS(p, AT);
    WT_HAS(p, TIP);
    WT_HAS(p, "  window.SlothIso = { theme: theme, scheme: scheme, rgbOf: rgbOf, mix: mix, heatRGB: heatRGB, css: css,\n"
              "                      layout: layout, rails: rails, paint: paint, hit: hit, colAt: colAt,\n"
              "                      frame: frame, grid: grid, at: at, tip: tip };");
    /* One namespace object, defined once. */
    int n = 0;
    for (const char *q = strstr(p, "window.SlothIso ="); q; q = strstr(q + 1, "window.SlothIso =")) n++;
    WT_EQ(n, 1);
    /* Every string the module shows is text: no markup, no attribute,
     * no code from a string, no subresource. */
    char *m = slice(ISO_FROM, ISO_TO);
    WT_ASSERT(m != NULL);
    if (m) {
        static const char *const sinks[] = {
            "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "setAttribute",
            "eval(", "new Function", ".src =", ".href =", "fetch(", "localStorage",
        };
        for (size_t i = 0; i < sizeof(sinks) / sizeof(sinks[0]); i++) WT_LACKS(m, sinks[i]);
        WT_HAS(m, "      d.textContent = String(l[0]);");
        WT_HAS(m, "        g.fillText(lab, cx, base0 + 12);");
        free(m);
    }
}

/* The cell grid the WiFi and BLE Devices tabs draw with, whole: its
 * renderer (the scale guarded against no extent, the columns' order,
 * the band names, the newest cell in front), its overlay and redraw;
 * and each caller whole: the channels in gridRows()'s band order on the
 * window's largest cell, the classes on the cells select's, the
 * advertisers on -110 to -30 dBm, the picked cell's row and time
 * swapped into the grid's column and row. */
static void test_iso_grid_and_callers_pinned(void) {
    const char *p = page();
    WT_HAS(p, RAILS);
    WT_HAS(p, GRID_RENDER);
    WT_HAS(p, GRID_OVERLAY);
    WT_HAS(p, GRID);
    WT_HAS(p, W_ISO_GRID);
    WT_HAS(p, BLE_CLASS_ISO);
    WT_HAS(p, BLE_PROX_ISO);
    WT_HAS(p, "  var PROX_LO = -110, PROX_HI = -30;");
}

/* The module is included once, before app.js and every tab that draws
 * with it, and the stylesheet with it. */
static void test_included_before_its_users(void) {
    const char *p = page();
    const char *iso = strstr(p, ISO_FROM);
    const char *app = strstr(p, "  // ── WiFi (§8.8, M5) ──");
    const char *spec = strstr(p, SPEC_FROM);
    const char *ble = strstr(p, "// slothweb: the BLE Devices view's waterfall");
    WT_ASSERT(iso && app && spec && ble);
    WT_ASSERT(iso && app && iso < app);
    WT_ASSERT(iso && spec && iso < spec);
    WT_ASSERT(iso && ble && iso < ble);
    WT_HAS(p, ".iso-tip { position: fixed;");
}

/* Spectrum draws through SlothIso and no longer carries its own
 * projection, painter, hit test or offscreen copy. */
static void test_spectrum_uses_iso(void) {
    const char *p = page();
    WT_HAS(p, SPEC_DRAW);
    char *s = slice(SPEC_FROM, SPEC_TO);
    WT_ASSERT(s != NULL);
    if (!s) return;
    WT_HAS(s, "  var ISO = window.SlothIso;\n  var rgbOf = ISO.rgbOf, theme = ISO.theme, css = ISO.css;");
    WT_HAS(s, "    geo = ISO.layout({ W: W, Hh: Hh, n: n, L: 46, R: timed() ? 112 : 70, top: 70, bottom: 54, deep: timed() || n > 12 });");
    WT_HAS(s, "    ISO.rails(g, T, geo);");
    WT_HAS(s, "    ISO.paint(g, T, geo, {\n"
              "      cols: cols, depth: depthOf,\n"
              "      value: function (idx, c) {\n"
              "        var a = bins[c], b = Math.max(a, bins[c + 1] - 1), q = colMax(rows[idx].q, a, b);\n"
              "        return q ? Math.max(0, Math.min(1, (qDb(q) - lr[0]) / span)) : 0;\n"
              "      },");
    WT_HAS(s, "var tip = $(\"spec-tip\"), idx = ISO.hit(geo, x, y);");
    /* The axes, the band strip and the peak labels stay the tab's. */
    WT_HAS(s, "    bandStrip(g, T, L, base0 + 32, PW);\n    peakLabels(g, T, lr, span);");
    static const char *const gone[] = {
        "function rowAt(", "function heatRGB(", "function rgbOf(", "function mix(",
        "var off = null", "order.sort(", "new Float32Array(", "pal.push(",
    };
    for (size_t i = 0; i < sizeof(gone) / sizeof(gone[0]); i++) {
        if (strstr(s, gone[i])) fprintf(stderr, "    spectrum.js still has %s\n", gone[i]);
        WT_LACKS(s, gone[i]);
    }
    free(s);
}

/* The toggles: a labelled checkbox per tab, checked in the markup,
 * isometric unless the viewer kept flat, the default kept as nothing. */
static void test_toggles_default_to_iso(void) {
    const char *p = page();
    WT_HAS(p, "\"><input type=\"checkbox\" id=\"w-iso\" checked> isometric</label>");
    WT_HAS(p, "\"><input type=\"checkbox\" id=\"bledev-iso\" checked> isometric</label>");
    WT_HAS(p, "             iso: true, ist: { off: null, dirty: true, geo: null, hover: null, o: null } };");
    WT_HAS(p, "  WF.iso = prefGet(\"wifi.iso\") !== false;\n  $(\"w-iso\").checked = WF.iso;");
    WT_HAS(p, "    prefSet(\"wifi.iso\", WF.iso ? null : false);");
    WT_HAS(p, "            iso: true, ist: isoState(), pist: isoState() };");
    WT_HAS(p, "    S.iso = H.prefGet(\"bledev.iso\") !== false;\n    $(\"bledev-iso\").checked = S.iso;");
    WT_HAS(p, "      H.prefSet(\"bledev.iso\", S.iso ? null : false);");
    WT_HAS(p, "    prefGet: prefGet, prefSet: prefSet });");
    /* The panels' modes, the words read out with them, the pick. */
    WT_HAS(p, CHANNEL_GRID);
    WT_HAS(p, ISO_PICK);
    WT_HAS(p, BLE_ISO_MODE);
    WT_HAS(p, BLE_ISO_PICK);
    /* The flat grids keep their keys; isometric moves across and back. */
    WT_HAS(p, "    var MOVE = WF.iso ? { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }\n"
              "                      : { ArrowLeft: [0, -1], ArrowRight: [0, 1], ArrowUp: [-1, 0], ArrowDown: [1, 0] };");
    WT_HAS(p, "    var MOVE = S.iso ? { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }\n"
              "                     : { ArrowLeft: [0, -1], ArrowRight: [0, 1], ArrowUp: [-1, 0], ArrowDown: [1, 0] };");
    WT_HAS(p, "<div class=\"iso-tip\" id=\"w-iso-tip\" role=\"tooltip\" hidden></div>");
    WT_HAS(p, "<div class=\"iso-tip\" id=\"bledev-iso-tip\" role=\"tooltip\" hidden></div>");
}

/* No tag in the page's markup carries an inline handler (on...=): the
 * CSP's hash admits the one script block and nothing an attribute
 * would run. The markup is everything outside the <script> and
 * <style> blocks. */
static void test_no_inline_handler(void) {
    const char *p = page();
    const char *ss = strstr(p, "<script>"), *se = ss ? strstr(ss, "</script>") : NULL;
    const char *ys = strstr(p, "<style>"), *ye = ys ? strstr(ys, "</style>") : NULL;
    WT_ASSERT(ss && se && ys && ye);
    int tags = 0, bad = 0;
    for (const char *q = strchr(p, '<'); q; q = strchr(q + 1, '<')) {
        if ((ss && se && q > ss && q < se) || (ys && ye && q > ys && q < ye)) continue;
        if (!((q[1] >= 'a' && q[1] <= 'z') || (q[1] >= 'A' && q[1] <= 'Z'))) continue;
        const char *gt = strchr(q, '>');
        if (!gt) break;
        tags++;
        for (const char *a = q; a + 3 < gt; a++) {
            if (a[0] != ' ' && a[0] != '\n' && a[0] != '\t') continue;
            if ((a[1] | 0x20) != 'o' || (a[2] | 0x20) != 'n') continue;
            const char *e = a + 3;
            while (e < gt && ((*e | 0x20) >= 'a' && (*e | 0x20) <= 'z')) e++;
            if (e > a + 3 && e < gt && *e == '=') {
                fprintf(stderr, "    inline handler: %.50s\n", a + 1);
                bad++;
            }
        }
    }
    WT_ASSERT(tags > 500);
    WT_EQ(bad, 0);
}

/* Owner 2026-11-17 ("on the spectrum displays for wifi and bluetooth I
 * want you to color code finding by band channel and ssid"): colour is
 * identity, height the value. The scheme's pieces whole: the colours
 * read from iso.css at each draw, the segment painter, the channel
 * classifier, the WiFi column body and key, the BLE class hues, steps
 * and grouping. The classifier's answers (2.4 GHz 1/6/11 against the
 * overlapping rest, the four 5 GHz U-NII steps with 2A and 2C under
 * DFS and "other" for 68-96 (U-NII-2B) and 169 up (U-NII-4),
 * 6 GHz ch % 16 == 5) were run in node on 1, 3, 6, 11, 13, 36, 48, 52,
 * 64, 68, 96, 100, 144, 149, 165, 169, 177, 6g1, 6g5, 6g21, 6g33, 6g37
 * and an unknown band; the suite runs no script, so the classifier is held by its
 * text, which is the rule as written. */
/* The proximity panel's grouped order and the pick carried across it
 * and across a refresh (new row objects) by the advertiser's identity,
 * not its old index: the block whole. */
static const char BLE_PROX_REMAP[] =
        "    if (S.iso) rows = byClass(rows);\n"
        "    var was = S.pcur ? S.prows[S.pcur.r] : null, at = was ? rows.findIndex(function (r) {\n"
        "      return r === was || (r.addr === was.addr && r.addr_type === was.addr_type && r.iface === was.iface);\n"
        "    }) : -1;\n"
        "    if (at >= 0 && at !== S.pcur.r) S.pcur = { r: at, c: S.pcur.c };\n"
        "    S.prows = rows;\n";

static void test_identity_scheme_pinned(void) {
    WT_HAS(page(), BLE_PROX_REMAP);
    const char *p = page();
    WT_HAS(p, SCHEME);
    WT_HAS(p, SEG_PAINTER);
    WT_HAS(p, COLOR_CACHE);
    WT_HAS(p, CHAN_SHADE);
    WT_HAS(p, W_ISO_SEGS);
    WT_HAS(p, W_ISO_KEY);
    WT_HAS(p, BLE_COLOURS);
    WT_HAS(p, BLE_CLASS_SEGS);
    WT_HAS(p, BLE_CLASS_KEY);
    /* The SSID colour is the page's one SSID colour (txColor()), and the
     * tooltip names the channel's step in words. */
    WT_HAS(p, "      out.push({ f: m[e + 1] / m[0], color: txColor(t), alpha: !off && (hl === null || ssidOf(t) === hl) ? 1 : ISO_FADE });");
    WT_HAS(p, "      [chanWord(chanShade(r.band, r.key)), true],");
    /* The keys' containers, and each shown only isometric. */
    WT_HAS(p, "<div class=\"iso-key\" id=\"w-iso-key\" role=\"group\" aria-label=\"colour key: bands, channels and SSIDs\" hidden></div>");
    WT_HAS(p, "<div class=\"iso-key\" id=\"bledev-cls-key\" role=\"group\" aria-label=\"colour key: device classes\"></div>");
    WT_HAS(p, "<div class=\"iso-key\" id=\"bledev-prox-key\" role=\"group\" aria-label=\"colour key: device classes\"></div>");
    WT_HAS(p, "    $(\"bledev-cls-key\").hidden = $(\"bledev-prox-key\").hidden = !S.iso || noSensor();");
}

/* Every token the scheme reads is written for both themes, and every
 * class in bledev.js's CLASSES table has its hue: read from the table
 * itself, so a class added there without a colour fails here. Seen red
 * with the light theme's --iso-c-hid line removed from iso.css, and with
 * "b:iot" dropped from scheme() (there by SCHEME's pin; the per-class
 * check reads the page, not the pin). */
static void test_identity_tokens_both_themes(void) {
    const char *p = page();
    const char *dark = strstr(p, "  --iso-c-phone: #5b9bff;");
    const char *light = strstr(p, ":root[data-theme=\"light\"] {\n  --iso-c-phone:");
    WT_ASSERT(dark && light && dark < light);
    /* Since 2026-11-18 a WiFi channel is the page's one channel colour
     * (test_chan.c); the band hue families are gone, not kept beside it.
     * Seen red with an --iso-b24-0 line put back in iso.css. */
    WT_LACKS(p, "--iso-b");
    char *cls = slice("  var CLASSES = [", "  var CLASS_OF = {};");
    WT_ASSERT(cls != NULL);
    if (!cls) return;
    int classes = 0;
    for (const char *q = strstr(cls, "{ slug: \"b:"); q; q = strstr(q + 1, "{ slug: \"b:")) {
        const char *a = q + strlen("{ slug: \"b:"), *z = strchr(a, '"');
        if (!z || z - a > 16) break;
        char want[96], name[24];
        memcpy(name, a, (size_t)(z - a));
        name[z - a] = '\0';
        classes++;
        snprintf(want, sizeof want, "--iso-c-%s:", name);
        int n = 0;
        for (const char *r = strstr(p, want); r; r = strstr(r + 1, want)) n++;
        if (n != 2) fprintf(stderr, "    %s written %d times\n", want, n);
        WT_EQ(n, 2);
        snprintf(want, sizeof want, "\"b:%s\": cssVar(\"--iso-c-%s\"", name, name);
        WT_HAS(p, want);
    }
    WT_EQ(classes, 7);
    free(cls);
}

/* Owner 2026-11-17: "don't remove any text labels". Colour is added on
 * top: every name the grid drew before it still draws, and none waits on
 * a colour. The grid renderer's text calls are counted (eight: the empty
 * words, the level ticks, the unit, the clock, the column names, the
 * group names, and since the client lane its name and each column's
 * count) and each pinned, and the callers still hand every name over.
 * Seen red with the column-name fillText deleted from iso.js (count 5),
 * with the group's fillText made conditional on a floor, and with the
 * lane's name drawn only when a lane count is nonzero. */
static void test_grid_labels_all_drawn(void) {
    char *r = slice("  function gridRender(st) {", "  function gridOverlay(st) {");
    WT_ASSERT(r != NULL);
    if (!r) return;
    int n = 0;
    for (const char *q = strstr(r, "fillText("); q; q = strstr(q + 1, "fillText(")) n++;
    WT_EQ(n, 8);
    WT_HAS(r, "        g.fillText(o.empty || \"no data\", 16, 24);");
    WT_HAS(r, "        g.fillText(o.fmt ? o.fmt(tk[k]) : String(tk[k]), geo.L - 4, yy + 3);");
    WT_HAS(r, "        g.fillText(o.unit, 0, 0); g.restore();");
    WT_HAS(r, "        g.fillText(o.clock(o.from + k * o.col_s), x + 8, y + 3);");
    WT_HAS(r, "            g.fillText(lab, cx, base0 + 12);");
    WT_HAS(r, "          if (gl && g.measureText(gl).width < z - a) { g.fillStyle = o.cols[gs].groupColor || T.ink; g.fillText(gl, (a + z) / 2, base0 + 29 + fy + ly); }");
    /* The floor strip and the lane only move the group's rule and name
     * down. */
    WT_HAS(r, "      var geo = layout({ W: W, Hh: Hh, n: n, L: 44, R: 56, top: 14, bottom: (grouped ? 34 : 22) + fy + ly, deep: n > 12 });");
    WT_HAS(r, "        g.fillStyle = T.muted; g.textAlign = \"left\";\n        g.fillText(lane.name, 1, lcy + 3);");
    WT_HAS(r, "          if (wide) { g.fillStyle = T.ink; g.fillText(lt, lx + rr + 2, lcy + 3); }");
    WT_LACKS(r, "lmax > 0) g.fillText");
    WT_LACKS(r, "floor) g.fillText");
    free(r);
    const char *p = page();
    WT_HAS(p, "        return { label: r.key, short: r.key.replace(/^6g/, \"\"), group: BAND_WORD[r.band] || \"band unknown\",");
    WT_HAS(p, "        return { label: d.glyph + \" \" + d.label, short: d.glyph, floor: { color: hue }, cap: hue };");
    WT_HAS(p, "      name: \"clients\", count: function (i) { return per[i].n; },");
    WT_HAS(p, "        return { label: r.name !== null ? r.name : shortAddr(r.addr), short: d.glyph,\n"
              "                 group: d.label, groupShort: d.glyph, groupColor: hue[i], floor: { color: hue[i] }, cap: hue[i] };");
}

/* paint() with no segments and no cap makes the heat ramp's calls as
 * before (the Spectrum tab's picture): the plain branch is the old body
 * and cap, line for line, and the new paths are reached only through
 * o.segments and o.cap. The canvas calls of the old and new iso.js were
 * recorded in node and compared equal on a 7x96 grouped grid, 24x96,
 * 5x3, 3x10 and a 50-column 30-row Spectrum-style paint. */
static void test_paint_plain_path_unchanged(void) {
    char *m = slice("  function paint(g, T, geo, o) {", "  // A column's body as segments");
    WT_ASSERT(m != NULL);
    if (!m) return;
    WT_HAS(m, "    var seg = o.segments ? segPainter(g, T, dense) : null, capOf = o.cap ? colorCache(g) : null;");
    WT_HAS(m, "        else {\n"
              "          g.fillStyle = pal[Math.round(f * 64)];\n"
              "          g.fillRect(x0 + c * PW / cols + gp, y0 - hpx, PW / cols + 0.6 - 2 * gp, hpx);\n"
              "        }\n");
    WT_HAS(m, "        else if (dense) { g.fillStyle = cap[Math.round(f * 64)]; g.fillRect(x0 + c * PW / cols + gp, y0 - hpx, PW / cols + 0.6 - 2 * gp, Math.min(1.5, hpx)); }");
    /* Spectrum hands paint() neither. */
    char *s = slice(SPEC_FROM, SPEC_TO);
    WT_ASSERT(s != NULL);
    if (s) { WT_LACKS(s, "segments:"); WT_LACKS(s, "cap:"); free(s); }
    free(m);
}

/* The client lane: its functions whole, the tooltip's line wired in, the
 * fade the owner set ("when highlighting an ssid on the water fall make
 * all the others 70 percent transparent", 2026-11-17) one constant that
 * the SSID chips and the client pick both use, an SSID and a client
 * never highlighted together, and every peer string (vendor, SSID,
 * BSSID) text: the block holds no markup sink. Seen red with
 * "innerHTML" added in a comment to clientKey(), with the SSID chip's
 * "WF.pc = null" removed, and with ISO_FADE set back to 0.25. */
static void test_client_lane_pinned(void) {
    const char *p = page();
    WT_HAS(p, W_ISO_CLIENTS);
    WT_HAS(p, W_ISO_TIP_CLIENTS);
    WT_HAS(p, "      [isoTipClients(r, at.k), true]\n    ].filter(function (l) { return l[0] !== \"\"; }), ev);");
    WT_HAS(p, "  var ISO_FADE = 0.3;\n");
    WT_LACKS(p, "  var ISO_FADE = 0.25;");
    WT_HAS(p, "          if (WF.hl !== null) WF.pc = null;");
    WT_HAS(p, "        if (WF.pc !== null) WF.hl = null;");
    WT_HAS(p, "      lane: lane, pick: pick,");
    WT_HAS(p, "fade every other one to 70 percent transparent, again to show all.");
    char *b = slice("  // ── the client lane (owner 2026-11-17", "  // Hover: the column under the pointer");
    WT_ASSERT(b != NULL);
    if (b) {
        static const char *const sinks[] = {
            "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "setAttribute",
            "eval(", "new Function",
        };
        for (size_t i = 0; i < sizeof(sinks) / sizeof(sinks[0]); i++) WT_LACKS(b, sinks[i]);
        free(b);
    }
}

void run_iso_tests(void) {
    WT_RUN(test_iso_module_pinned);
    WT_RUN(test_iso_grid_and_callers_pinned);
    WT_RUN(test_included_before_its_users);
    WT_RUN(test_spectrum_uses_iso);
    WT_RUN(test_toggles_default_to_iso);
    WT_RUN(test_no_inline_handler);
    WT_RUN(test_identity_scheme_pinned);
    WT_RUN(test_identity_tokens_both_themes);
    WT_RUN(test_grid_labels_all_drawn);
    WT_RUN(test_paint_plain_path_unchanged);
    WT_RUN(test_client_lane_pinned);
}
