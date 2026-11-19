/* The Devices view's waterfall (owner 2026-11-19: "add a waterfall
 * graph to the devices pages so we can see when devices appear and
 * reappear over time"; web/ui/devwf.js, GET /api/devices/arrivals,
 * whose counting test_devices.c's test_arrivals_classes holds).
 *
 * What is pinned: the panel and its hooks, that it is the isometric grid
 * the WiFi and BLE waterfalls draw (iso.js) with the hours across and
 * the days receding, that a column's body is the three kinds in their
 * order as shares of the hour's devices, that an hour still to come is
 * not drawn, and that nothing reaches a markup sink. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "wtest.h"

static const char *page(void) { return (const char *)web_page; }

static void test_devwf_page(void) {
    const char *p = page();
    WT_HAS(p, "<section class=\"panel\" id=\"d-wf-panel\">");
    WT_HAS(p, "<canvas class=\"wfall iso d-wf\" id=\"d-wf\"");
    WT_HAS(p, "<select id=\"d-wf-days\"><option value=\"1\">1</option><option value=\"3\">3</option>"
              "<option value=\"7\" selected>7</option>");
    WT_HAS(p, "    if (v === \"devices\" && window.SlothDevWf) SlothDevWf.show();");
    WT_HAS(p, "  if (window.SlothDevWf) SlothDevWf.init({ getJSON: getJSON, errText: errText, fmt: fmt,\n"
              "                                           prefGet: prefGet, prefSet: prefSet });");
    WT_HAS(p, "canvas.wfall.d-wf { height: 300px; }");
    /* iso.js is the page's before the module draws with it. */
    const char *iso = strstr(p, "window.SlothIso = {");
    const char *wf = strstr(p, "window.SlothDevWf = {");
    WT_ASSERT(iso && wf && iso < wf);
}

static void test_devwf_drawing(void) {
    const char *p = page();
    const char *a = strstr(p, "// slothweb: the Devices view's waterfall");
    const char *b = a ? strstr(a, "\n})();") : NULL;
    WT_ASSERT(a && b);
    if (!a || !b) return;
    WT_HAS(a, "  var KINDS = [\n"
              "    { k: \"arrived\", label: \"arrived (none in the 24 h before)\", tok: \"--heat-3\", fb: \"#ff6a3d\" },\n"
              "    { k: \"back\", label: \"back (absent the hour before)\", tok: \"--info-1\", fb: \"#4fc3f7\" },\n"
              "    { k: \"still\", label: \"still here (present the hour before)\", tok: \"--phosphor-dim\", fb: \"#2b8f74\" }\n"
              "  ];");
    WT_HAS(a, "  function segs(j, i, colors) {\n"
              "    var p = j.present[i];\n"
              "    if (!num(p) || p <= 0) return null;\n"
              "    var out = [];\n"
              "    for (var n = 0; n < KINDS.length; n++) {\n"
              "      var v = j[KINDS[n].k][i];\n"
              "      if (num(v) && v > 0) out.push({ f: v / p, color: colors[n] });\n"
              "    }\n"
              "    return out.length ? out : null;\n"
              "  }");
    WT_HAS(a, "  function cell(k, c) { return k * 24 + c; }");
    /* The hours across, the days receding; a null hour (to come) no
     * value, so no column. */
    WT_HAS(a, "      cols: cols, n: nd, from: j ? j.from : 0, col_s: 86400,\n"
              "      value: function (k, c) { var v = j.present[cell(k, c)]; return num(v) ? v : null; },");
    WT_HAS(a, "    H.getJSON(\"/api/devices/arrivals?days=\" + days()).then(function (j) {");
    for (const char *q = a; q < b; q++) {
        WT_ASSERT(strncmp(q, "innerHTML", 9) != 0);
        WT_ASSERT(strncmp(q, "insertAdjacentHTML", 18) != 0);
    }
}

void run_devwf_tests(void) {
    WT_RUN(test_devwf_page);
    WT_RUN(test_devwf_drawing);
}
