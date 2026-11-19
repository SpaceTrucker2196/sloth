/* The larger time graphs drawn isometrically (owner 2026-11-19: "for
 * the larger graphs in the ui when there is a time domain express that
 * in the isometric waterfall graph format like we have for spectrum
 * using color coding where appropriate"; "all 4"): web/ui/isochart.js,
 * window.SlothIsoChart, drawing through SlothIso.grid (iso.js) the
 * Overview's now vs normal, the WiFi clients chart, deauth and
 * probe-flood rugs, the Activity band and all-keys charts and the
 * device drawer's week.
 *
 * The suite runs no script, so the page is held by its text: the pure
 * half (where a value sits against its band, how a window folds into
 * rows, the folding of points and lane cells, the probe-flood lanes,
 * the key columns, a week cell's state) and the box and its sync pinned
 * whole; each picture's colouring lines; each panel's box a checkbox
 * checked in the markup, read as isometric unless the viewer kept
 * "flat" and written as no value for the default; each hook where its
 * flat chart is drawn; the module after iso.js; the CSS that hides the
 * flat canvas, and the isometric one with a flat one app.js hid. The
 * pure half was run under node against hand-worked cases and the
 * pictures, tooltips and boxes were looked at in headless Chromium
 * against the demo and synthetic answers (2026-11-19).
 *
 * Each absence assertion here was seen red before it was trusted, and
 * restored byte-identical from a copy: the sink scan with a comment
 * naming innerHTML added to isochart.js; the second projection scan
 * with a stub "function layout(" added to isochart.js; the order with
 * @include isochart.js moved before iso.js. Review (2026-11-19): the
 * paint, insertAdjacentHTML and outerHTML scans, each red with a
 * comment naming it put inside the module (one put after
 * window.SlothIsoChart is outside what module() reads, and is caught
 * only by the page-wide scans in test_alerts.c and test_bundle.c). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "wtest.h"

static const char *page(void) { return (const char *)web_page; }

static char *module(void) {
    const char *a = strstr(page(), "// slothweb: the larger time graphs as isometric waterfalls");
    const char *b = a ? strstr(a, "window.SlothIsoChart = {") : NULL;
    if (!a || !b) return NULL;
    char *out = malloc((size_t)(b - a) + 1);
    if (!out) return NULL;
    memcpy(out, a, (size_t)(b - a));
    out[b - a] = '\0';
    return out;
}

static const char JS_STATES[] =
    "  var STATES = [\n"
    "    { k: \"above\", label: \"above its band\", tok: \"--heat-3\", fb: \"#ff3f3f\" },\n"
    "    { k: \"within\", label: \"within its band\", tok: \"--tui-normal\", fb: \"#2b8f74\" },\n"
    "    { k: \"below\", label: \"below its band\", tok: \"--data\", fb: \"#4cebff\" },\n"
    "    { k: \"none\", label: \"no band yet (warming)\", tok: \"--heat-0\", fb: \"#626262\" }\n"
    "  ];";

static const char JS_WHERE[] =
    "  function where(v, b) {\n"
    "    if (!num(v)) return -1;\n"
    "    if (!b || !num(b[0]) || !num(b[1])) return 3;\n"
    "    return v > b[1] ? 0 : v < b[0] ? 2 : 1;\n"
    "  ";

static const char JS_SHAPE[] =
    "  function shape(from, to, step, off) {\n"
    "    var win = to - from;\n"
    "    if (win >= 172800) {\n"
    "      var d0 = from - ((from + off) % 86400 + 86400) % 86400;\n"
    "      return { days: true, from: d0, n: Math.ceil((to - d0) / 86400), cols: 24, row_s: 86400, cell_s: 3600 };\n"
    "    }\n"
    "    var cells = Math.max(1, Math.round(win / Math.max(1, step)));\n"
    "    // Under 60 steps (a window glyph.win() shrank to a few minutes of\n"
    "    // data): rows of about 4 cells, at most 8, the ridge spacing's own.\n"
    "    var n = cells < 60 ? Math.min(8, Math.ceil(cells / 4)) : win <= 10800 ? 15 : 24, row = win / n;\n"
    "    var cols = Math.max(1, Math.min(60, Math.round(row / Math.max(1, step))));\n"
    "    return { days: false, from: from, n: n, cols: cols, row_s: row, cell_s: row / cols };\n"
    "  ";

static const char JS_FOLD[] =
    "  function fold(pts, band, sh) {\n"
    "    var N = sh.n * sh.cols, acc = [], i;\n"
    "    for (i = 0; i < N; i++) acc.push(null);\n"
    "    for (i = 0; pts && i < pts.length; i++) {\n"
    "      var t = pts[i][0], v = pts[i][1];\n"
    "      if (!num(t) || !num(v) || t < sh.from) continue;\n"
    "      var k = Math.floor((t - sh.from) / sh.row_s);\n"
    "      if (k >= sh.n) continue;\n"
    "      var c = Math.min(sh.cols - 1, Math.floor((t - sh.from - k * sh.row_s) / sh.cell_s));\n"
    "      var a = acc[k * sh.cols + c] || (acc[k * sh.cols + c] = { v: 0, n: 0, lo: 0, hi: 0, mean: 0, nb: 0 });\n"
    "      a.v += v; a.n++;\n"
    "      var b = band && band[i];\n"
    "      if (b) { a.lo += b[0]; a.hi += b[1]; a.mean += b[2]; a.nb++; }\n"
    "    }\n"
    "    return acc.map(function (a) {\n"
    "      if (!a) return null;\n"
    "      return { v: a.v / a.n, n: a.n, b: a.nb ? [a.lo / a.nb, a.hi / a.nb, a.mean / a.nb] : null };\n"
    "    });\n"
    "  ";

static const char JS_FOLDROW[] =
    "  function foldRow(cells, g, how) {\n"
    "    var out = [];\n"
    "    for (var a = 0; a < cells.length; a += g) {\n"
    "      var s = 0, n = 0, mx = null;\n"
    "      for (var i = a; i < a + g && i < cells.length; i++) {\n"
    "        if (!num(cells[i])) continue;\n"
    "        s += cells[i]; n++;\n"
    "        if (mx === null || cells[i] > mx) mx = cells[i];\n"
    "      }\n"
    "      out.push(!n ? null : how === \"max\" ? mx : how === \"mean\" ? s / n : s);\n"
    "    }\n"
    "    return out;\n"
    "  ";

static const char JS_INSPAN[] =
    "  function inSpan(spans, g, k) {\n"
    "    for (var i = 0; spans && i < spans.length; i++)\n"
    "      if (Math.floor(spans[i][0] / g) <= k && k <= Math.floor(spans[i][1] / g)) return true;\n"
    "    return false;\n"
    "  ";

static const char JS_SEVLANES[] =
    "  function sevLanes(rows, from, to, cols) {\n"
    "    var col_s = (to - from) / cols, out = [];\n"
    "    function col(t) { return Math.max(0, Math.min(cols - 1, Math.floor((t - from) / col_s))); }\n"
    "    for (var sv = 2; sv >= 0; sv--) {\n"
    "      var counts = [], spans = [], i;\n"
    "      for (i = 0; i < cols; i++) counts.push(0);\n"
    "      for (i = 0; rows && i < rows.length; i++) {\n"
    "        var r = rows[i];\n"
    "        if (r.sev !== sv || !num(r.first_seen) || !num(r.last_seen)) continue;\n"
    "        if (r.last_seen < from || r.first_seen >= to) continue;\n"
    "        if (r.first_seen >= from) counts[col(r.first_seen)]++;\n"
    "        spans.push([col(r.first_seen), col(r.last_seen)]);\n"
    "      }\n"
    "      if (spans.length) out.push({ sev: sv, counts: counts, spans: spans });\n"
    "    }\n"
    "    return out;\n"
    "  ";

static const char JS_BINPTS[] =
    "  function binPts(pts, from, row_s, n, how) {\n"
    "    var cells = [], i;\n"
    "    for (i = 0; i < n; i++) cells.push([]);\n"
    "    for (i = 0; pts && i < pts.length; i++) {\n"
    "      var k = Math.floor((pts[i][0] - from) / row_s);\n"
    "      if (k >= 0 && k < n && num(pts[i][1])) cells[k].push(pts[i][1]);\n"
    "    }\n"
    "    return cells.map(function (c) { return c.length ? foldRow(c, c.length, how)[0] : null; });\n"
    "  ";

static const char JS_KEYCOLS[] =
    "  function keyCols(n, max, pick) {\n"
    "    var out = [];\n"
    "    for (var i = 0; i < n && i < max; i++) out.push(i);\n"
    "    if (pick >= max && pick < n) out[out.length - 1] = pick;\n"
    "    return out;\n"
    "  ";

static const char JS_WEEKSTATE[] =
    "  function weekState(cell, warm) {\n"
    "    if (!cell || !num(cell[1]) || cell[1] <= 0) return -1;\n"
    "    return cell[1] >= warm ? 0 : 1;\n"
    "  ";

static const char JS_LOCALOFF[] =
    "  function localOff(t) {\n"
    "    var d = new Date(t * 1000);\n"
    "    return Math.round((Date.UTC(d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(),\n"
    "                                d.getMinutes(), d.getSeconds()) - Math.floor(t) * 1000) / 1000);\n"
    "  ";

/* A day-folded picture's tooltip on the clock its columns are labelled
 * in (the sensor's offset), not the browser's: review 2026-11-19. */
static const char JS_HMAT[] =
    "  function hmAt(t, off) {\n"
    "    var d = new Date((t + off) * 1000);\n"
    "    return pad2(d.getUTCHours()) + \":\" + pad2(d.getUTCMinutes());\n"
    "  ";

static const char JS_BANDTIP[] =
    "    function when(t) { return sh.days ? dayWord(t, off) + \" \" + hmAt(t, off) : hm(t); }\n"
    "    function till(t) { return sh.days ? hmAt(t, off) : hm(t); }\n";

static const char JS_BANDTIPLINES[] =
    "        return [[when(s) + \" to \" + till(s + sh.cell_s)],\n"
    "                [H.fmt(x.v) + unit + (x.n > 1 ? \" (mean of \" + x.n + \")\" : \"\")],\n"
    "                [x.b ? \"band \" + H.fmt(x.b[0]) + \" to \" + H.fmt(x.b[1]) + unit + \", mean \" + H.fmt(x.b[2])\n"
    "                     : \"no band for this hour yet (warming)\", true],\n"
    "                [STATES[w].label, true]];";

static const char JS_DUR[] =
    "  function dur(s) {\n"
    "    s = Math.round(s);\n"
    "    if (s < 60) return s + \"s\";\n"
    "    var sec = s % 60;\n"
    "    if (s < 3600) return Math.floor(s / 60) + \"m\" + (sec ? pad2(sec) + \"s\" : \"\");\n"
    "    var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);\n"
    "    return h + \"h\" + (m || sec ? pad2(m) : \"\") + (sec ? \"m\" + pad2(sec) + \"s\" : \"\");\n"
    "  }";

static const char JS_SYNC[] =
    "  function sync(id) {\n"
    "    var p = chart(id), f = $(id), cv = $(id + \"-iso\"), k = $(id + \"-iso-key\");\n"
    "    if (f) f.classList.toggle(\"iso-off\", p.on);\n"
    "    if (cv) cv.hidden = !p.on;\n"
    "    if (k) k.hidden = !p.on;\n"
    "    if (!p.on) { p.st.hover = null; tipShow(null, null); }\n"
    "    return p.on && cv && f && !f.hidden ? cv : null;\n"
    "  ";

static const char JS_BOX[] =
    "  function box(bid, pref, ids, redraw) {\n"
    "    var b = $(bid);\n"
    "    if (!b) return;\n"
    "    var on = H.prefGet(pref) !== false;\n"
    "    b.checked = on;\n"
    "    ids.forEach(function (id) { chart(id).on = on; sync(id); });\n"
    "    b.addEventListener(\"change\", function () {\n"
    "      on = b.checked;\n"
    "      H.prefSet(pref, on ? null : false);\n"
    "      ids.forEach(function (id) { chart(id).on = on; chart(id).st.dirty = true; sync(id); });\n"
    "      redraw();\n"
    "    });\n"
    "    ids.forEach(function (id) {\n"
    "      var cv = $(id + \"-iso\");\n"
    "      if (!cv) return;\n"
    "      cv.addEventListener(\"pointermove\", function (ev) {\n"
    "        var p = chart(id), at = p.d ? SlothIso.at(cv, p.st, ev) : null, lines = at && p.tip ? p.tip(at) : null;\n"
    "        p.st.hover = lines ? at : null;\n"
    "        tipShow(lines, ev);\n"
    "        SlothIso.grid(cv, p.st);\n"
    "      });\n"
    "      cv.addEventListener(\"pointerleave\", function (ev) {\n"
    "        var p = chart(id);\n"
    "        if (!p.st.hover) return;\n"
    "        p.st.hover = null;\n"
    "        tipShow(null, ev);\n"
    "        SlothIso.grid(cv, p.st);\n"
    "      });\n"
    "      cv.addEventListener(\"click\", function (ev) {\n"
    "        var p = chart(id), at = p.d && p.click ? SlothIso.at(cv, p.st, ev) : null;\n"
    "        if (at) p.click(at);\n"
    "      });\n"
    "    });\n"
    "  ";

static void test_isochart_pure(void) {
    char *m = module();
    WT_ASSERT(m != NULL);
    if (!m) return;
    WT_HAS(m, JS_STATES);
    WT_HAS(m, JS_WHERE);
    WT_HAS(m, JS_SHAPE);
    WT_HAS(m, JS_FOLD);
    WT_HAS(m, JS_FOLDROW);
    WT_HAS(m, JS_INSPAN);
    WT_HAS(m, JS_SEVLANES);
    WT_HAS(m, JS_BINPTS);
    WT_HAS(m, JS_KEYCOLS);
    WT_HAS(m, JS_WEEKSTATE);
    WT_HAS(m, JS_LOCALOFF);
    WT_HAS(m, JS_HMAT);
    WT_HAS(m, JS_DUR);
    free(m);
}

/* Each picture: SlothIso.grid and nothing of its own projection; its
 * colour from where(), a flood span, a severity, a key, a week state. */
static void test_isochart_drawing(void) {
    char *m = module();
    WT_ASSERT(m != NULL);
    if (!m) return;
    WT_HAS(m, "          value: function (k, c) { var x = at(k, c); return x ? Math.max(x.v, lo + (hi - lo) * 0.03) : null; },");
    WT_HAS(m, "            return x ? [{ f: 1, color: cs[where(x.v, x.b)] }] : null;");
    WT_HAS(m, "    var sh = shape(d.from, d.to, d.step, off), cells = fold(d.pts, d.band, sh);");
    WT_HAS(m, "          segments: function (k, c) { return [{ f: 1, color: inSpan(lanes[c].spans, g, k) ? crit : cc[c] }]; },");
    WT_HAS(m, "    var rows = ((j && j.bssids) || []).filter(SlothAir.busy).slice(0, 12);");
    WT_HAS(m, "    var id = \"w-pflood\", p = chart(id), lanes = rows ? sevLanes(rows, from, to, cols) : [];");
    WT_HAS(m, "    var idx = keyCols(d.rows.length, COLS_KEYS, d.pick), how = d.presence ? \"max\" : \"mean\";");
    WT_HAS(m, "            return weekState(x, warm) < 0 ? null : Math.max(num(x[0]) ? x[0] : 0, 0.03);");
    WT_HAS(m, "          segments: function (k, c) { return weekState(at(k, c), warm) === 1 ? [{ f: 1, color: dim }] : null; },");
    WT_HAS(m, "    SlothIso.grid(cv, p.st, o);");
    WT_HAS(m, JS_BANDTIP);
    WT_HAS(m, JS_BANDTIPLINES);
    /* An unknown channel in the flat rug's own --tui-dim. */
    WT_HAS(m, "        var crit = cssVar(\"--sev-crit\", \"#ff3f3f\"), dim = cssVar(\"--tui-dim\", \"#00875f\");");
    WT_HAS(m, JS_SYNC);
    WT_HAS(m, JS_BOX);
    /* One projection: iso.js's. */
    WT_LACKS(m, "function layout(");
    WT_LACKS(m, "function paint(g");
    /* No markup sink; every string by textContent or fillText. */
    WT_LACKS(m, "innerHTML");
    WT_LACKS(m, "insertAdjacentHTML");
    WT_LACKS(m, "outerHTML");
    free(m);
    WT_HAS(page(), "  window.SlothAir = { init: function (h) { H = h; }, horizon: horizon, drill: drill, rug: rug,\n"
                   "                      floodRug: floodRug, busy: busy, ROW: ROW };");
}

/* Each panel's box, its canvas beside the flat one, its hook. */
static void test_isochart_page(void) {
    const char *p = page();
    const char *iso = strstr(p, "window.SlothIso = {");
    const char *ic = strstr(p, "window.SlothIsoChart = {");
    const char *app = strstr(p, "  function overview() {");
    WT_ASSERT(iso && ic && app && iso < ic && ic < app);
    static const char *const BOX[] = { "o-iso", "w-ch-iso", "w-pc-iso", "a-iso", "dr-iso" };
    for (size_t i = 0; i < sizeof(BOX) / sizeof(BOX[0]); i++) {
        char want[96];
        snprintf(want, sizeof(want), "<input type=\"checkbox\" id=\"%s\" checked> isometric</label>", BOX[i]);
        WT_HAS(p, want);
    }
    /* Each isometric canvas straight after its flat one (iso.css's
     * sibling rule hides it with a flat one app.js hid), hidden until
     * the box is read. */
    WT_HAS(p, "<canvas class=\"chart\" id=\"o-nvn\" aria-label=\"throughput against its baseline band\"></canvas>\n"
              "        <canvas class=\"wfall iso isoc\" id=\"o-nvn-iso\"");
    WT_HAS(p, "flood episodes underlined\"></canvas>\n      <canvas class=\"wfall iso isoc\" id=\"w-deauth-iso\"");
    WT_HAS(p, "underlined to its last sighting\" hidden></canvas>\n      <canvas class=\"wfall iso isoc rug-iso\" id=\"w-pflood-iso\"");
    WT_HAS(p, "over their baseline band\"></canvas>\n      <canvas class=\"wfall iso isoc\" id=\"w-probe-iso\"");
    WT_HAS(p, "id=\"a-chart\" height=\"240\" aria-label=\"band chart\"></canvas>\n      <canvas class=\"wfall iso isoc\" id=\"a-chart-iso\"");
    WT_HAS(p, "the legend below lists them\"></canvas>\n        <canvas class=\"wfall iso isoc\" id=\"ak-chart-iso\"");
    WT_HAS(p, "Monday first\"></canvas>\n    <canvas class=\"wfall iso isoc week-iso\" id=\"dr-week-iso\"");
    WT_HAS(p, "<div class=\"iso-tip\" id=\"isoc-tip\" role=\"tooltip\" hidden></div>\n  <footer");
    WT_HAS(p, "canvas.iso-off { display: none; }\n"
              "[hidden] + canvas.isoc, [hidden] + canvas.isoc + .iso-key { display: none; }");
    /* The boxes, kept per viewer only when flat. */
    WT_HAS(p, "    SlothIsoChart.box(\"o-iso\", \"nvn.iso\", [\"o-nvn\"], function () { if (view === \"overview\") overview(); });");
    WT_HAS(p, "    SlothIsoChart.box(\"w-ch-iso\", \"wrug.iso\", [\"w-deauth\", \"w-pflood\"], function () { if (view === \"wifi\") wifi(); });");
    WT_HAS(p, "    SlothIsoChart.box(\"w-pc-iso\", \"wprobe.iso\", [\"w-probe\"], function () { if (view === \"wifi\") wifi(); });");
    WT_HAS(p, "    SlothIsoChart.box(\"a-iso\", \"act.iso\", [\"a-chart\", \"ak-chart\"], function () { if (view === \"activity\") refresh(); });");
    WT_HAS(p, "    SlothIsoChart.box(\"dr-iso\", \"drweek.iso\", [\"dr-week\"], function () {");
    /* The hooks, beside each flat drawing. */
    WT_HAS(p, "          draw($(\"o-nvn\"), s.points, opt);\n"
              "          if (window.SlothIsoChart) SlothIsoChart.band(\"o-nvn\", { pts: s.points, band: bd, from: gw.from, to: gw.to,\n"
              "            step: s.step, off: bl ? bl.utc_offset_s : null, unit: \"B/s\", now: now });");
    WT_HAS(p, "      if (window.SlothIsoChart) SlothIsoChart.band(\"a-chart\", { pts: s.points, band: bd, from: gw.from, to: gw.to,\n"
              "        step: s.step, off: r[1] ? r[1].utc_offset_s : null, unit: m.unit, now: now });");
    WT_HAS(p, "      if (window.SlothIsoChart) SlothIsoChart.band(\"w-probe\", s.points.length ? { pts: s.points, band: pbd,");
    WT_HAS(p, "      var rg = SlothAir.rug($(\"w-deauth\"), j), nb = rg.busy;\n"
              "      if (window.SlothIsoChart) SlothIsoChart.deauth(j);");
    WT_HAS(p, "        if (window.SlothIsoChart) SlothIsoChart.pflood(rows, r.from, r.to, 96);");
    WT_HAS(p, "      if (window.SlothIsoChart) SlothIsoChart.week(\"dr-week\", wk);");
    WT_HAS(p, "      SlothIsoChart.allkeys({ rows: S.rows, from: presence ? head.from : S.view.o.from,");
    WT_HAS(p, "    SlothIsoChart.init({ fmt: fmt, hhmmss: hhmmss, prefGet: prefGet, prefSet: prefSet });");
}

void run_isochart_tests(void) {
    WT_RUN(test_isochart_pure);
    WT_RUN(test_isochart_drawing);
    WT_RUN(test_isochart_page);
}
