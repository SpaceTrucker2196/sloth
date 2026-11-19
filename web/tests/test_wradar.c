/* The WiFi view's radar scope (owner 2026-11-19: "add a radar view to
 * the wifi page like we have for ads-b and aprs"; web/ui/wradar.js on
 * ppi.js).
 *
 * What is pinned: the panel and its hooks, that the scope is ppi.js's
 * (the ADS-B and APRS one) and not a second drawing, that a device is
 * placed by its distance and direction finding's bearing only (an
 * arbitrary, steady angle from its address when there is none, drawn
 * hollow), that the sensor's coordinates are never read (the origin is
 * a fixed point, not /api/gnss), that the colour is the channel's from
 * chan.js, and that nothing reaches a markup sink. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "wtest.h"

static const char *page(void) { return (const char *)web_page; }

static const char *module(const char **end) {
    const char *p = page();
    const char *a = strstr(p, "// slothweb: the WiFi view's radar scope");
    const char *b = a ? strstr(a, "\n})();") : NULL;
    *end = b;
    return a && b ? a : NULL;
}

static void test_wradar_page(void) {
    const char *p = page();
    WT_HAS(p, "<section class=\"panel\" id=\"w-radar-panel\">");
    WT_HAS(p, "<canvas id=\"w-radar\" class=\"heat\"");
    WT_HAS(p, "<select id=\"w-radar-range\"><option value=\"0\" selected>auto</option>");
    WT_HAS(p, "    if (v === \"wifi\" && window.SlothWRadar) SlothWRadar.show();");
    WT_HAS(p, "  if (window.SlothWRadar) SlothWRadar.init({ getJSON: getJSON, errText: errText, openDrawer: openDrawer });");
    /* ppi.js is the page's before the module runs its show(). */
    const char *ppi = strstr(p, "window.SlothPPI = {");
    const char *wr = strstr(p, "window.SlothWRadar = {");
    WT_ASSERT(ppi && wr && ppi < wr);
}

static void test_wradar_placement(void) {
    const char *end = NULL, *a = module(&end);
    WT_ASSERT(a != NULL);
    if (!a) return;
    WT_HAS(a, "  function addrAngle(mac) {\n"
              "    var ad = String(mac).toLowerCase(), h = 2166136261;\n"
              "    for (var i = 0; i < ad.length; i++) { h ^= ad.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }\n"
              "    return (h >>> 8) % 360;\n"
              "  }");
    WT_HAS(a, "  function dfBearing(mac) {\n"
              "    var r = window.SlothDf && SlothDf.of ? SlothDf.of(mac) : null;\n"
              "    return r && num(r.bearing_deg) && r.bearing_deg >= 0 && r.bearing_deg < 360 ? r.bearing_deg : null;\n"
              "  }");
    WT_HAS(a, "  function at(az, m) {\n"
              "    var a = az * Math.PI / 180;\n"
              "    return { lat: ORIGIN.lat + m * Math.cos(a) / M_PER_DEG, lon: ORIGIN.lon + m * Math.sin(a) / M_PER_DEG };\n"
              "  }");
    /* Solid only with a bearing; the colour is the channel's. */
    WT_HAS(a, "      var br = dfBearing(dv.mac), az = br === null ? addrAngle(dv.mac) : br, p = at(az, dv.m);");
    /* A cluster's blocks: the picked one kept, then the farthest first,
     * the rest marks only. */
    WT_HAS(a, "      if (clash && !o.picked) { o.lines = []; return; }");
    WT_HAS(a, "    var rg = range(devs), tg = declutter(targets(devs, S.picked), rg);");
    WT_HAS(a, "      var col = ch !== null && window.SlothChan ? SlothChan.rgb(ch) : null;");
    WT_HAS(a, "      out.push({ id: String(dv.mac), lat: p.lat, lon: p.lon, color: col || \"#8a82a0\", fill: br !== null,");
    WT_HAS(a, "      if (!num(dv.m) || dv.m < 0) return;");
    WT_HAS(a, "    var r = S.ppi.scope({ centre: ORIGIN, range: rg, unit: UNIT, targets: tg,");
    WT_HAS(a, "  var ORIGIN = { lat: 0, lon: 0 };");
    WT_HAS(a, "    H.getJSON(\"/api/radar\").then(function (j) {");
    /* The sensor's position is never read, and nothing is markup. */
    for (const char *q = a; q < end; q++) {
        WT_ASSERT(strncmp(q, "/api/gnss", 9) != 0);
        WT_ASSERT(strncmp(q, "SlothPPI.centre", 15) != 0);
        WT_ASSERT(strncmp(q, "innerHTML", 9) != 0);
        WT_ASSERT(strncmp(q, "insertAdjacentHTML", 18) != 0);
    }
}

void run_wradar_tests(void) {
    WT_RUN(test_wradar_page);
    WT_RUN(test_wradar_placement);
}
