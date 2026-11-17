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
        "        g.fillStyle = pal[Math.round(f * 64)];\n"
        "        g.fillRect(x0 + c * PW / cols + gp, y0 - hpx, PW / cols + 0.6 - 2 * gp, hpx);\n"
        "        if (dense) { g.fillStyle = cap[Math.round(f * 64)]; g.fillRect(x0 + c * PW / cols + gp, y0 - hpx, PW / cols + 0.6 - 2 * gp, Math.min(1.5, hpx)); }\n"
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
        "      var geo = layout({ W: W, Hh: Hh, n: n, L: 44, R: 56, top: 14, bottom: grouped ? 34 : 22, deep: n > 12 });\n"
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
        "        }\n"
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
        "          g.beginPath(); g.moveTo(a + 2, base0 + 18.5); g.lineTo(z - 2, base0 + 18.5); g.stroke();\n"
        "          var gl = o.cols[gs].group || \"\";\n"
        "          if (gl && g.measureText(gl).width < z - a) { g.fillStyle = T.ink; g.fillText(gl, (a + z) / 2, base0 + 29); }\n"
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
        "    var cur = WF.cur;\n"
        "    SlothIso.grid(c, WF.ist, {\n"
        "      cols: rows.map(function (r) {\n"
        "        return { label: r.key, short: r.key.replace(/^6g/, \"\"), group: BAND_WORD[r.band] || \"band unknown\" };\n"
        "      }),\n"
        "      n: rows.length ? cols : 0, from: hz ? hz.from : 0, col_s: hz ? hz.col_s : 0,\n"
        "      value: function (k, i) { var cl = rows[i].heat && rows[i].heat.cells; return cl ? cl[k] : null; },\n"
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
        "    var cur = S.cur;\n"
        "    SlothIso.grid($(\"bledev-classes\"), S.ist, {\n"
        "      cols: rows.map(function (r) { var d = classDef(r.key); return { label: d.glyph + \" \" + d.label, short: d.glyph }; }),\n"
        "      n: rows.length ? cols : 0, from: from, col_s: col_s,\n"
        "      value: function (k, i) { var cl = rows[i].heat && rows[i].heat.cells; return cl ? cl[k] : null; },\n"
        "      lo: 0, hi: hmax > 0 ? hmax : 1, ticks: hmax > 0 ? [0, hmax / 2, hmax] : [0], unit: classUnit(), fmt: H.fmt,\n"
        "      clock: H.hhmmss, sel: cur && cur.r < rows.length && cur.c < cols ? { k: cur.c, c: cur.r } : null,\n"
        "      empty: S.cls ? \"no class in the window\" : \"loading\"\n"
        "    });\n"
        "  }";

static const char BLE_PROX_ISO[] =
        "  function proxIso(rows, p) {\n"
        "    var cur = S.pcur, cols = p && p.cols ? p.cols : 0;\n"
        "    SlothIso.grid($(\"bledev-prox\"), S.pist, {\n"
        "      cols: rows.map(function (r) {\n"
        "        var d = classDef(r[\"class\"]);\n"
        "        return { label: r.name !== null ? r.name : shortAddr(r.addr), short: d.glyph };\n"
        "      }),\n"
        "      n: rows.length ? cols : 0, from: p ? p.from : 0, col_s: p ? p.col_s : 0,\n"
        "      value: function (k, i) { return rows[i].cells ? rows[i].cells[k] : null; },\n"
        "      lo: PROX_LO, hi: PROX_HI, ticks: [-100, -80, -60, -40], unit: \"dBm (mean)\",\n"
        "      fmt: function (v) { return String(v); }, clock: H.hhmmss,\n"
        "      sel: cur && cur.r < rows.length && cur.c < cols ? { k: cur.c, c: cur.r } : null,\n"
        "      empty: p ? \"no advertiser heard in the window\" : \"loading\"\n"
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
    WT_HAS(p, "  window.SlothIso = { theme: theme, rgbOf: rgbOf, mix: mix, heatRGB: heatRGB, css: css,\n"
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

void run_iso_tests(void) {
    WT_RUN(test_iso_module_pinned);
    WT_RUN(test_iso_grid_and_callers_pinned);
    WT_RUN(test_included_before_its_users);
    WT_RUN(test_spectrum_uses_iso);
    WT_RUN(test_toggles_default_to_iso);
    WT_RUN(test_no_inline_handler);
}
