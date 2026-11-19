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
    WT_HAS(p, "      if (notes[i].hidden) continue;");
    WT_HAS(p, "    b.ariaLabel = (title ? title + \": \" : \"\") + \"source and description\";");
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
    WT_RUN(test_info_order);
}
