/* The page's source and description notes behind info buttons (owner
 * 2026-11-18: "move all source and description text that is usually in
 * light grey to dialogs behind info buttons. the goal of this is a more
 * efficient less cluttered display"; web/ui/info.js, info.css).
 *
 * What is pinned: which .sub is a note (and so which is not: a state, a
 * count, an error, a control's label), that a note stays in the
 * document and only its display goes, that the dialog is built from
 * copies of the page's own nodes with no markup sink, and that info.js
 * runs before app.js's main() so a note is judged on index.html's
 * words. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "wtest.h"

static const char *page(void) { return (const char *)web_page; }

static void test_info_rule(void) {
    const char *p = page();
    WT_HAS(p, "  var MIN = 60;\n"
              "  var SKIP = \".label, label, dialog, details, .drawer, .scope-legend, [role], [aria-live]\";");
    WT_HAS(p, "  function isNote(e) {\n"
              "    if (e.className !== \"sub\") return false;\n"
              "    if (e.closest(\".kpis\")) return false;\n"
              "    if (e.closest(SKIP)) return false;\n"
              "    return e.textContent.replace(/\\s+/g, \" \").trim().length >= MIN;\n"
              "  }");
    /* Hidden, never removed: the scripts showing one of a set still do. */
    WT_HAS(p, "      e.classList.add(\"info-src\");");
    WT_HAS(p, ".sub.info-src { display: none; }");
}

static void test_info_dialog(void) {
    const char *p = page();
    const char *a = strstr(p, "// slothweb: the page's source and description notes go behind info");
    const char *b = a ? strstr(a, "\n})();") : NULL;
    WT_ASSERT(a && b);
    if (!a || !b) return;
    /* No markup sink in info.js: copies of the page's own nodes only. */
    for (const char *q = a; q < b; q++) {
        WT_ASSERT(strncmp(q, "innerHTML", 9) != 0);
        WT_ASSERT(strncmp(q, "insertAdjacentHTML", 18) != 0);
    }
    WT_HAS(p, "    var c = note.cloneNode(true), ids = c.querySelectorAll(\"[id]\"), i;\n"
              "    c.removeAttribute(\"id\");\n"
              "    for (i = 0; i < ids.length; i++) ids[i].removeAttribute(\"id\");");
    /* Only what the view shows now. */
    WT_HAS(p, "      if (notes[i].hidden || blank(notes[i])) continue;");
    WT_HAS(p, "    b.ariaLabel = (title ? title + \": \" : \"\") + \"source and description\";");
}

/* The Overview's KPI tiles (owner 2026-11-19: "put the grey text behind
 * an info icon on the bottom of the tile"): every .sub in a tile, short
 * or script-written, behind one button in a row at the tile's foot, and
 * the tiles taken before the general pass. */
static void test_info_tiles(void) {
    const char *p = page();
    WT_HAS(p, "  function tiles() {\n"
              "    var ts = document.querySelectorAll(\".kpis .tile\"), i, j, subs, lab, foot;\n"
              "    for (i = 0; i < ts.length; i++) {\n"
              "      subs = ts[i].querySelectorAll(\".sub\");\n"
              "      if (!subs.length) continue;\n"
              "      for (j = 0; j < subs.length; j++) subs[j].classList.add(\"info-src\");\n"
              "      lab = ts[i].querySelector(\".label\");\n"
              "      foot = document.createElement(\"div\");\n"
              "      foot.className = \"tile-foot\";\n"
              "      foot.appendChild(button(lab ? labelText(lab) : \"\", Array.prototype.slice.call(subs)));\n"
              "      ts[i].appendChild(foot);\n"
              "    }\n"
              "  }");
    WT_HAS(p, "  function init() {\n    tiles();\n");
    WT_HAS(p, "  function blank(e) {\n"
              "    var t = e.textContent.replace(/\\s+/g, \" \").trim();\n"
              "    return t === \"\" || t === \"-\";\n"
              "  }");
    WT_HAS(p, ".tile .tile-foot { display: flex; justify-content: flex-end; margin-top: 6px; }");
    /* The button's click stays off the tile's link. */
    WT_HAS(p, "      ev.preventDefault();\n      ev.stopPropagation();\n      open(title, notes);");
    /* Every tile has grey lines for it to take. */
    const char *k = strstr(p, "<section class=\"kpis\"");
    const char *e = k ? strstr(k, "</section>") : NULL;
    WT_ASSERT(k && e);
    int tiles = 0;
    for (const char *q = k; q && q < e && (q = strstr(q, "<a class=\"tile hud\"")) && q < e; q++) tiles++;
    WT_EQ(tiles, 7);
}

static void test_info_order(void) {
    const char *p = page();
    const char *info = strstr(p, "window.SlothInfo = {");
    const char *app = strstr(p, "document.addEventListener(\"DOMContentLoaded\", main);");
    WT_ASSERT(info && app && info < app);
    /* The greenbar stays the last stylesheet. */
    const char *css = strstr(p, ".sub.info-src { display: none; }");
    const char *gb = strstr(p, ":root { --gb-toward: #ffffff; }");
    WT_ASSERT(css && gb && css < gb);
}

void run_info_tests(void) {
    WT_RUN(test_info_rule);
    WT_RUN(test_info_dialog);
    WT_RUN(test_info_tiles);
    WT_RUN(test_info_order);
}
