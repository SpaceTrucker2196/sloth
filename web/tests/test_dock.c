/* The detail column (owner 2026-11-19: "the UI has a column that is 1/4
 * of the width for the same view ... when you click something that
 * opens a detail view it creates a new row of that detail view in the
 * scroll view"; web/ui/dock.js, dock.css).
 *
 * What is pinned out of the served page: the column and its width, that
 * each of the four openers and closes tells the column, that the
 * column's own functions are whole (opened(), closed(), esc(), the
 * tick), that Esc closes only the detail the focus is in, that dock.js
 * has no markup sink, and that it is loaded before app.js lends it the
 * page's helpers. The behaviour itself needs a browser: it was driven
 * in headless Chrome on 2026-11-19 and is not asserted here. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "wtest.h"

static const char *page(void) { return (const char *)web_page; }

static void test_dock_markup(void) {
    const char *p = page();
    WT_HAS(p, "  <div class=\"work\" id=\"work\">\n  <main>\n");
    WT_HAS(p, "  <aside class=\"dock\" id=\"dock\" aria-label=\"details\">");
    WT_HAS(p, "<button type=\"button\" id=\"dock-toggle\" aria-expanded=\"true\" aria-controls=\"dock-list\"");
    WT_HAS(p, "<div class=\"dock-list\" id=\"dock-list\">");
    /* A quarter of the page, beside the views; a rail when folded; over
     * the page when narrow, and then absent with nothing open. */
    WT_HAS(p, ".dock { flex: 0 0 25%; width: 25%; min-width: 0; position: sticky;");
    WT_HAS(p, ".dock.min { flex-basis: 30px; width: 30px; }");
    WT_HAS(p, "  .dock.empty { display: none; }");
    /* In a card the drawer is not a fixed overlay. */
    WT_HAS(p, ".dock .drawer { position: static; width: auto;");
    /* The kinds' elements are still the page's, one each. */
    const char *ids[] = { "<aside class=\"drawer\" id=\"drawer\" hidden", "<aside class=\"drawer\" id=\"bdrawer\" hidden",
                          "<aside class=\"drawer\" id=\"sdrawer\" hidden", "<aside class=\"drawer\" id=\"kdrawer\" hidden" };
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        const char *a = strstr(p, ids[i]);
        WT_ASSERT(a != NULL);
        if (a) WT_ASSERT(strstr(a + 1, ids[i]) == NULL);
    }
}

static void test_dock_hooks(void) {
    const char *p = page();
    /* Every opener's first act and every close's last. */
    WT_HAS(p, "    var gen = ++DR.gen;\n"
              "    if (window.SlothDock) SlothDock.opened(\"device\", [mac], mac);\n");
    WT_HAS(p, "    DR.back = null;\n"
              "    if (window.SlothDock) SlothDock.closed(\"device\");\n  }\n");
    WT_HAS(p, "    var gen = ++BDR.gen;\n"
              "    if (window.SlothDock) SlothDock.opened(\"ble\", [addr, type === undefined ? null : type, "
              "iface === undefined ? null : iface], addr);\n");
    WT_HAS(p, "    BDR.back = null;\n"
              "    if (window.SlothDock) SlothDock.closed(\"ble\");\n  }\n");
    WT_HAS(p, "    if (window.SlothDock) window.SlothDock.opened(\"ssid\", [disp === undefined ? null : disp],\n"
              "                                                  p === \"-\" ? \"(hidden)\" : String(disp));\n");
    WT_HAS(p, "    if (window.SlothDock) window.SlothDock.closed(\"ssid\");\n  }\n");
    WT_HAS(p, "    if (window.SlothDock) window.SlothDock.opened(\"karma\", [bssid], bssid);\n");
    WT_HAS(p, "    if (window.SlothDock) window.SlothDock.closed(\"karma\");\n  }\n");
    /* Esc: the detail the focus is in, not every one. */
    WT_HAS(p, "    if (e.key === \"Escape\") {\n"
              "      if (!window.SlothDock || SlothDock.esc(\"device\")) closeDrawer();\n"
              "      if (!window.SlothDock || SlothDock.esc(\"ble\")) closeBleDrawer();\n"
              "      scopeLegend(false);\n"
              "      return;\n"
              "    }");
    WT_HAS(p, "      if (e.key === \"Escape\" && (!window.SlothDock || window.SlothDock.esc(\"karma\"))) close();\n");
    /* An alert opened from a detail no longer closes it. */
    WT_HAS(p, "      if (window.SlothDock) { window.SlothDock[\"yield\"](); return; }\n");
    /* The four kinds, lent with the page's helpers. */
    WT_HAS(p, "      device: { aside: \"drawer\", closeBtn: \"dr-close\", word: \"device\", swatch: true,\n"
              "                open: function (a) { openDrawer(a[0]); }, close: closeDrawer },\n"
              "      ble: { aside: \"bdrawer\", closeBtn: \"bdr-close\", word: \"ble\", swatch: false,\n"
              "             open: function (a) { openBleDrawer(a[0], a[1], a[2]); }, close: closeBleDrawer },\n");
}

static void test_dock_module(void) {
    const char *p = page();
    const char *a = strstr(p, "// The detail column (owner request 2026-11-19)");
    const char *b = a ? strstr(a, "\n})();") : NULL;
    WT_ASSERT(a && b);
    if (!a || !b) return;
    /* No markup sink: createElement and textContent only. */
    for (const char *q = a; q < b; q++) {
        WT_ASSERT(strncmp(q, "innerHTML", 9) != 0);
        WT_ASSERT(strncmp(q, "insertAdjacentHTML", 18) != 0);
        WT_ASSERT(strncmp(q, "setAttribute", 12) != 0);
        WT_ASSERT(strncmp(q, "document.write", 14) != 0);
    }
    WT_HAS(p, "  var TICK_MS = 3000, REFRESH_S = 15, SUMMARY_S = 30, MAX = 24;");
    WT_HAS(p, "  function opened(kind, args, title) {\n"
              "    var k = K[kind];\n"
              "    if (!H || !k) return;\n"
              "    var key = JSON.stringify(args), c = find(kind, key), cur = openCard(kind);\n"
              "    if (cur && cur !== c) toLine(cur);\n"
              "    if (!c) c = make(kind, key, args, String(title));\n"
              "    if (k.aside.parentNode !== c.body) c.body.appendChild(k.aside);\n"
              "    if (c.min) { c.min = false; paint(c); }\n"
              "    c.refAt = now();\n"
              "    count();\n"
              "    if (S.quiet) return;\n"
              "    save();\n"
              "    fold(false, true);\n");
    WT_HAS(p, "  function closed(kind) {\n"
              "    var c = openCard(kind);\n"
              "    if (!c) return;\n"
              "    if (S.folding) { toLine(c); return; }\n"
              "    c.min = true;\n"
              "    remove(c);\n"
              "  }");
    WT_HAS(p, "  function esc(kind) {\n"
              "    var k = K[kind];\n"
              "    if (!k || overlay()) return false;\n"
              "    return !k.aside.hidden && k.aside.contains(document.activeElement);\n"
              "  }");
    /* The kind's element outlives its card. */
    WT_HAS(p, "    if (k.aside.parentNode === c.body) { k.aside.hidden = true; $(\"app\").appendChild(k.aside); }");
    /* Nothing asked while the tab is hidden or the column folded, and
     * one request a tick. */
    WT_HAS(p, "  function tick() {\n"
              "    if (!H || document.hidden || S.min) return;\n");
    WT_HAS(p, "    if (due) { due.refAt = t; refresh(due); return; }\n");
    /* A kept list is checked before it is believed. */
    WT_HAS(p, "        if (!r || !K[r.k] || !okArgs(r.a) || typeof r.t !== \"string\" || r.t.length > 128) return;");
    /* A MAC or an SSID reaches the server only as an encoded segment. */
    WT_HAS(p, "H.getJSON(\"/api/device/\" + encodeURIComponent(a[0]))");
    WT_HAS(p, "H.getJSON(\"/api/wifi/ssid?ssid=\" + encodeURIComponent(p))");
    WT_HAS(p, "H.getJSON(\"/api/lures/bssid?bssid=\" + encodeURIComponent(a[0]))");
}

static void test_dock_order(void) {
    const char *p = page();
    const char *dock = strstr(p, "window.SlothDock = {");
    const char *app = strstr(p, "document.addEventListener(\"DOMContentLoaded\", main);");
    WT_ASSERT(dock && app && dock < app);
    /* The greenbar stays the last stylesheet. */
    const char *css = strstr(p, ".dock .drawer { position: static;");
    const char *gb = strstr(p, ":root { --gb-toward: #ffffff; }");
    WT_ASSERT(css && gb && css < gb);
}

void run_dock_tests(void) {
    WT_RUN(test_dock_markup);
    WT_RUN(test_dock_hooks);
    WT_RUN(test_dock_module);
    WT_RUN(test_dock_order);
}
