/* The page's settings kept in this browser (owner request 2026-10-27:
 * "the whole UI should keep settings between launches where it is
 * changeable"). The suite runs no script, so the page is held by its
 * text: one versioned namespace reached only through the three store
 * functions, each in a try; the keys from before it moved; every table's
 * widths and sort kept by the one table implementation, a kept width
 * held to the column's floor and a kept sort to a column that still
 * sorts; every form control the page has decided, kept or not, so a new
 * one cannot arrive undecided; the address winning over a kept view and
 * scope; a reset per table and one for everything. The behaviour (sort
 * and resize, reload, still there; reset) was seen in headless Chromium.
 *
 * Each absence assertion here was seen red before it was trusted, and
 * restored byte-identical: the store-only scan with the theme toggle's
 * old direct localStorage.setItem put back (it names the offset); the
 * every-control census with an undecided <select id="al-new"> added to
 * index.html (it names the control); the page's kept list with "al-win"
 * taken out of app.js's keepCtl list; the old key names with SCOPE_KEY
 * put back. The kept sort's sortable check and the address over a kept
 * view were each seen red with the guard taken out. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "wtest.h"

/* The store's section of app.js: the namespace's comment to the theme's. */
#define STORE_FROM "  // ── settings kept in this browser (owner request 2026-10-27) ──────"
#define STORE_TO   "  // The theme, before the first paint:"

/* No localStorage outside the store's three functions and the migration:
 * a setting written straight to the store would miss the namespace, the
 * try and "reset settings". */
static void test_one_namespace_one_door(void) {
    const char *p = (const char *)web_page;
    const char *a = strstr(p, STORE_FROM);
    const char *b = a ? strstr(a, STORE_TO) : NULL;
    WT_ASSERT(a != NULL && b != NULL);
    if (!a || !b) return;
    int outside = 0, inside = 0;
    for (const char *q = strstr(p, "localStorage"); q; q = strstr(q + 1, "localStorage")) {
        if (q > a && q < b) inside++;
        else {
            outside++;
            fprintf(stderr, "  localStorage outside the store at +%ld: %.60s\n", (long)(q - p), q);
        }
    }
    WT_EQ(outside, 0);
    WT_ASSERT(inside >= 4);
    WT_HAS(p, "  var PREF = \"slothweb.v1.\";");
    /* Every read and write in a try, a value that does not parse a null. */
    WT_HAS(p, "      var s = window.localStorage.getItem(PREF + name);\n"
              "      return s === null ? null : JSON.parse(s);\n"
              "    } catch (e) { return null; }");
    WT_HAS(p, "    } catch (e) { /* no storage: this load only */ }");
    WT_HAS(p, "    } catch (e) { /* no storage: nothing kept */ }");
    WT_HAS(p, "    } catch (e) { /* no storage: nothing to move */ }");
    /* The keys from before the namespace, moved, not lost. */
    WT_HAS(p, "if (k === \"slothweb.theme\") { to = \"theme\"; val = v; }");
    WT_HAS(p, "else if (k === \"slothweb.scope\") { to = \"scope\"; val = v; }");
    WT_HAS(p, "else if (k === \"slothweb.sensitivity\") { to = \"sens\"; val = Number(v); }");
    WT_HAS(p, "to = \"table.\" + k.slice(14);");
    WT_HAS(p, "if (to && val !== null && ls.getItem(PREF + to) === null) ls.setItem(PREF + to, JSON.stringify(val));");
    WT_LACKS(p, "SCOPE_KEY");
    WT_LACKS(p, "THEME_KEY");
    WT_LACKS(p, "SENS_KEY");
    WT_LACKS(p, "DT_STORE");
    /* The theme still before the first paint, from the store. */
    WT_HAS(p, "  if (prefGet(\"theme\") === \"light\") root.dataset.theme = \"light\";");
}

/* Every table, through the one DataTable: its widths and sort read
 * once and checked, written on each change, both forgotten by its
 * reset. */
static void test_tables_keep_widths_and_sort(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "    var v = prefGet(\"table.\" + id), out = { w: {}, key: null, dir: 0 };");
    WT_HAS(p, "Object.keys(v.w).forEach(function (k) { if (num(v.w[k])) out.w[k] = v.w[k]; });");
    WT_HAS(p, "if (typeof v.sort === \"string\" && (v.dir === 1 || v.dir === -1)) { out.key = v.sort; out.dir = v.dir; }");
    WT_HAS(p, "    prefSet(\"table.\" + t.o.id, Object.keys(v).length ? v : null);");
    WT_HAS(p, "    var kept = dtLoad(o.id);");
    /* A kept width clamped to the column's floor and 4000 px; a width
     * for a column the table no longer has is never asked for. */
    WT_HAS(p, "      if (!own.call(t.w, c.k) || !num(t.w[c.k])) return null;\n"
              "      return Math.max(t.min(c), Math.min(4000, Math.round(t.w[c.k])));");
    /* A kept sort only on a column that is there and sorts. */
    WT_HAS(p, "    var kc = kept.key ? t.col(kept.key) : null;\n"
              "    if (kc && t.sortable(kc)) { t.key = kept.key; t.dir = kept.dir; }");
    /* Written by a resize, a header click, a server sort picked
     * instead, and the reset. */
    WT_HAS(p, "      t.w[c.k] = Math.max(t.min(c), Math.min(4000, Math.round(px)));\n      dtSave(t);");
    WT_HAS(p, "      else { t.key = null; t.dir = 0; }\n      dtSave(t);");
    WT_HAS(p, "    t.clear = function () { t.key = null; t.dir = 0; dtSave(t); t.paint(); };");
    WT_HAS(p, "      t.dir = 0;\n      dtSave(t);\n      t.apply();");
    WT_HAS(p, "el(\"button\", \"dt-reset\", \"reset columns\")");
}

/* Every form control on the page, kept or decided not to be: a new
 * select, input or textarea fails here until it is one or the other. */
static const char *const KEPT[] = {
    /* by keepCtl(), by value */
    "n-win", "a-win", "d-q", "d-sort", "l-q", "w-metric", "w-win", "w-sort", "al-state",
    "al-sev", "al-q", "al-win", "f-win", "f-sort", "f-ip", "q-sql",
};
static const char *const KEPT_ELSEWHERE[] = {
    "sens",       /* slothweb.v1.sens, range-checked */
    "al-type",    /* filled from the answer: put back as ALP.wantType */
    "a-metric",   /* by name (act.metric): its options are indices */
    "a-key",      /* by key, per metric (act.keys) */
};
static const char *const NOT_KEPT[] = {
    "q-recipe",   /* an action: it fills the SQL box, whose text is kept */
};

static int listed(const char *id, const char *const *l, size_t n) {
    for (size_t i = 0; i < n; i++) if (strcmp(id, l[i]) == 0) return 1;
    return 0;
}
#define N_OF(a) (sizeof(a) / sizeof((a)[0]))

static void test_every_control_is_decided(void) {
    const char *p = (const char *)web_page;
    static const char *const TAG[] = { "<select id=\"", "<textarea id=\"", "<input type=\"" };
    int seen = 0;
    for (size_t t = 0; t < N_OF(TAG); t++) {
        for (const char *q = strstr(p, TAG[t]); q; q = strstr(q + 1, TAG[t])) {
            const char *idp = strstr(q, "id=\"");
            const char *gt = strchr(q, '>');
            if (!idp || !gt || idp > gt) { WT_ASSERT(0); continue; }
            idp += 4;
            const char *e = strchr(idp, '"');
            char id[64];
            size_t n = e ? (size_t)(e - idp) : 0;
            if (!e || n >= sizeof(id)) { WT_ASSERT(0); continue; }
            memcpy(id, idp, n);
            id[n] = '\0';
            seen++;
            int k = listed(id, KEPT, N_OF(KEPT)) + listed(id, KEPT_ELSEWHERE, N_OF(KEPT_ELSEWHERE)) +
                    listed(id, NOT_KEPT, N_OF(NOT_KEPT));
            if (k != 1) fprintf(stderr, "  control #%s is not decided (kept or not)\n", id);
            WT_EQ(k, 1);
        }
    }
    WT_ASSERT(seen >= 21);
    /* No control is made by the script: they would escape the census. */
    WT_LACKS(p, "el(\"select\"");
    WT_LACKS(p, "el(\"input\"");
    WT_LACKS(p, "createElement(\"input\")");
    WT_LACKS(p, "createElement(\"select\")");
    /* The kept list as the page has it, every id quoted in it. */
    const char *kl = strstr(p, "].forEach(keepCtl);");
    const char *ks = kl ? kl : NULL;
    while (ks && ks > p && ks[0] != '[') ks--;
    WT_ASSERT(kl != NULL && ks != NULL);
    if (kl && ks) {
        size_t len = (size_t)(kl - ks);
        char *list = malloc(len + 1);
        if (!list) return;
        memcpy(list, ks, len);
        list[len] = '\0';
        for (size_t i = 0; i < N_OF(KEPT); i++) {
            char q[80];
            snprintf(q, sizeof(q), "\"%s\"", KEPT[i]);
            WT_HAS(list, q);
        }
        free(list);
    }
    /* Each kept elsewhere, where it is. */
    WT_HAS(p, "  var savedSens = prefGet(\"sens\");");
    WT_HAS(p, "  $(\"al-type\").addEventListener(\"change\", function () { ctlSave(\"al-type\"); });");
    WT_HAS(p, "ALP.wantType = typeof VP.type === \"string\" ? VP.type : !named && typeof kt === \"string\" ? kt : \"\";");
    WT_HAS(p, "if (selMetric()) prefSet(\"act.metric\", selMetric().name);");
    WT_HAS(p, "if (A.key < 0) A.key = Math.max(0, A.keys.indexOf(actKey(m.name)));");
    /* A kept value only where the control can hold it. */
    WT_HAS(p, "for (var i = 0; i < c.options.length; i++) if (c.options[i].value === v) return true;");
    WT_HAS(p, "return v.length <= (c.maxLength > 0 ? c.maxLength : 65536);");
}

/* The rest of what a viewer changes: the view, the scope, the ticker's
 * pause, the collapsed chrome, the anomaly chips and mode, the flows
 * tab; and the address over all of it. */
static void test_the_rest_and_the_address(void) {
    const char *p = (const char *)web_page;
    /* A kept view only where the address names none, and only a tab's. */
    WT_HAS(p, "    if (NAV.indexOf(v) >= 0) prefSet(\"view\", v);");
    WT_HAS(p, "      if (!r && NAV.indexOf(kv) >= 0) r = { v: kv, p: {} };");
    /* The kept scope read first, the address's after it, so it wins. */
    const char *ks = strstr(p, "  var savedScope = prefGet(\"scope\");");
    const char *hs = strstr(p, "  if (hashScope) SCOPE = hashScope[1];");
    WT_ASSERT(ks != NULL && hs != NULL && ks < hs);
    WT_HAS(p, "    prefSet(\"scope\", s);");
    /* An address naming an alerts filter sets the others to defaults,
     * not to the kept ones: the link reproduces what it names. */
    WT_HAS(p, "$(\"al-state\").value = STATE_SET[VP.state] ? VP.state : named ? \"all\" : ctlKept(\"al-state\", \"all\");");
    WT_HAS(p, "if ($(\"d-q\").value === D.drill) $(\"d-q\").value = ctlKept(\"d-q\", \"\");");
    WT_HAS(p, "  var paused = prefGet(\"paused\") === true;");
    WT_HAS(p, "    prefSet(\"paused\", paused || null);");
    WT_HAS(p, "if (e.key === \"[\") prefSet(\"collapsed\", $(\"app\").classList.toggle(\"collapsed\") || null);");
    WT_HAS(p, "  if (prefGet(\"collapsed\") === true) $(\"app\").classList.add(\"collapsed\");");
    WT_HAS(p, "        prefSet(\"anom.kind\", N.kind || null);");
    WT_HAS(p, "  if (prefGet(\"anom.table\") === true) anomMode(true);");
    WT_HAS(p, "          prefSet(\"flows.proto\", p);");
    WT_HAS(p, "  if (FLOW_TABS.indexOf(prefGet(\"flows.proto\")) >= 0) F.proto = prefGet(\"flows.proto\");");
    /* An address picked from a flow row or the chord is the viewer's. */
    WT_HAS(p, "$(\"f-ip\").value = from; ctlSave(\"f-ip\"); flowRows(true);");
    /* A kept SQL draft is not replaced by the first recipe. */
    WT_HAS(p, "if (Q.recipes.length && !ctlKept(\"q-sql\", \"\")) $(\"q-sql\").value = Q.recipes[0].sql.trim();");
    /* "reset settings": everything, then the bare address loaded again. */
    WT_HAS(p, "id=\"prefs-reset\"");
    WT_HAS(p, "    prefClear();\n"
              "    try { window.history.replaceState(null, \"\", location.pathname + location.search); }");
    WT_HAS(p, "    location.reload();");
}

void run_prefs_tests(void) {
    WT_RUN(test_one_namespace_one_door);
    WT_RUN(test_tables_keep_widths_and_sort);
    WT_RUN(test_every_control_is_decided);
    WT_RUN(test_the_rest_and_the_address);
}
