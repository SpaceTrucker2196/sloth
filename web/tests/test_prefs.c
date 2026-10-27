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
 * view were each seen red with the guard taken out.
 *
 * The review's (2026-10-27), each seen red and restored byte-identical:
 * the census with <select class="x" id="al-new"> (attributes in another
 * order) and with an <input type="text"> with no id; the toggle census
 * with an undecided aria-pressed button and with an ariaPressed set on
 * #pause; the named-filter rule with al-q's old drillQ branch and with
 * al-win kept unconditionally; the drill-down with ALP.wantType back in
 * it; the no-save rule with a ctlSave in alertsView and in the devices
 * drill-down; the address scope with setScope's no-keep flag dropped;
 * the chip's own list with &kind from N.kind and with the open-only
 * filter narrowed by it again; dtSave writing every width; the
 * migration's and the reset's catch-all over slothweb.* put back. The
 * behaviour (a link's filters and scope applied, not kept; show all;
 * the chip's fetches; v2 keys surviving the move and the reset; a gone
 * column's width dropped) was driven in headless Chromium. */
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
    /* A kept width raised to the column's floor; one past 4000 px,
     * which no drag makes, ignored as corrupt rather than drawn 4000 px
     * wide (seen red with the > 4000 test removed); a width for a column
     * the table no longer has is never asked for. */
    WT_HAS(p, "      if (!own.call(t.w, c.k) || !num(t.w[c.k]) || t.w[c.k] > 4000) return null;\n"
              "      return Math.max(t.min(c), Math.round(t.w[c.k]));");
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

/* The id inside the tag that starts at q (its '<'), wherever in the
 * tag the attribute is; 0 when the tag has none or it does not fit. */
static int tag_id(const char *q, char *id, size_t cap) {
    const char *gt = strchr(q, '>');
    if (!gt) return 0;
    for (const char *a = q; a + 4 < gt; a++) {
        if ((a[0] == ' ' || a[0] == '\n' || a[0] == '\t') && strncmp(a + 1, "id=\"", 4) == 0) {
            const char *v = a + 5, *e = strchr(v, '"');
            if (!e || e > gt || (size_t)(e - v) >= cap) return 0;
            memcpy(id, v, (size_t)(e - v));
            id[e - v] = '\0';
            return 1;
        }
    }
    return 0;
}

static void test_every_control_is_decided(void) {
    const char *p = (const char *)web_page;
    /* Every <select, <textarea and <input tag, its attributes in any
     * order; a control with no id cannot be kept, so it fails too. */
    static const char *const TAG[] = { "<select", "<textarea", "<input" };
    int seen = 0;
    for (size_t t = 0; t < N_OF(TAG); t++) {
        size_t tl = strlen(TAG[t]);
        for (const char *q = strstr(p, TAG[t]); q; q = strstr(q + 1, TAG[t])) {
            char c = q[tl];
            if (c != ' ' && c != '\n' && c != '\t' && c != '>' && c != '/') continue;
            char id[64];
            if (!tag_id(q, id, sizeof(id))) {
                fprintf(stderr, "  control without an id: %.60s\n", q);
                WT_ASSERT(0);
                continue;
            }
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
    WT_HAS(p, "    if (!noKeep) prefSet(\"scope\", s);");
    /* An address naming an alerts filter sets the others to defaults,
     * not to the kept ones: the link reproduces what it names. */
    WT_HAS(p, "$(\"al-state\").value = STATE_SET[VP.state] ? VP.state : named ? \"all\" : ctlKept(\"al-state\", \"all\");");
    WT_HAS(p, "if ($(\"d-q\").value === D.drill) $(\"d-q\").value = ctlKept(\"d-q\", \"\");");
    WT_HAS(p, "  var paused = prefGet(\"paused\") === true;");
    WT_HAS(p, "    prefSet(\"paused\", paused || null);");
    WT_HAS(p, "if (e.key === \"[\") prefSet(\"collapsed\", $(\"app\").classList.toggle(\"collapsed\") || null);");
    WT_HAS(p, "  if (prefGet(\"collapsed\") === true) $(\"app\").classList.add(\"collapsed\");");
    WT_HAS(p, "    prefSet(\"anom.kind\", N.kind || null);");
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

/* The controls that are buttons: a toggle, a radio group, a chip set, a
 * tab set. Each is kept (its save line named) or not: one with ARIA
 * state in the page, or ARIA state set by the script, that is not here
 * fails. A chip set that only swaps a class escapes the scan, which is
 * why n-chips is listed by hand. */
struct toggle { const char *id; const char *save; };
static const struct toggle TOGGLES[] = {
    { "theme",      "    prefSet(\"theme\", light ? \"light\" : \"dark\");" },
    { "pause",      "    prefSet(\"paused\", paused || null);" },
    { "sc-monitor", "    b.addEventListener(\"click\", function () { pickScope(s); });" },
    { "sc-hybrid",  "    b.addEventListener(\"click\", function () { pickScope(s); });" },
    { "sc-local",   "    b.addEventListener(\"click\", function () { pickScope(s); });" },
    { "n-mode",     "    prefSet(\"anom.table\", N.table || null);" },
    { "n-chips",    "    prefSet(\"anom.kind\", N.kind || null);" },
    { "f-tabs",     "          prefSet(\"flows.proto\", p);" },
};
static const char *const TOGGLE_JS[] = {   /* the script's ARIA state, each a listed toggle's */
    "      b.ariaChecked = on ? \"true\" : \"false\";",
    "    $(\"n-mode\").ariaPressed = N.table ? \"true\" : \"false\";",
    "        b.ariaSelected = p === F.proto ? \"true\" : \"false\";",
};

static void test_every_toggle_is_decided(void) {
    const char *p = (const char *)web_page;
    for (size_t i = 0; i < N_OF(TOGGLES); i++) {
        char want[80];
        snprintf(want, sizeof(want), "id=\"%s\"", TOGGLES[i].id);
        WT_HAS(p, want);
        WT_HAS(p, TOGGLES[i].save);
    }
    static const char *const ATTR[] = { "aria-pressed=", "aria-checked=", "aria-selected=",
                                        "role=\"radio\"", "role=\"tab\"", "role=\"tablist\"",
                                        "role=\"switch\"", "role=\"checkbox\"" };
    int seen = 0;
    for (size_t a = 0; a < N_OF(ATTR); a++) {
        for (const char *q = strstr(p, ATTR[a]); q; q = strstr(q + 1, ATTR[a])) {
            if (q > p && q[-1] == '[') continue;     /* a stylesheet's selector */
            const char *lt = q;
            while (lt > p && *lt != '<' && *lt != '>') lt--;
            char id[64];
            if (*lt != '<' || !tag_id(lt, id, sizeof(id))) {
                fprintf(stderr, "  toggle without an id: %.60s\n", lt);
                WT_ASSERT(0);
                continue;
            }
            int k = 0;
            for (size_t i = 0; i < N_OF(TOGGLES); i++) if (strcmp(id, TOGGLES[i].id) == 0) k = 1;
            if (!k) fprintf(stderr, "  toggle #%s is not decided (kept or not)\n", id);
            WT_EQ(k, 1);
            seen++;
        }
    }
    WT_ASSERT(seen >= 8);
    static const char *const PROP[] = { "ariaPressed", "ariaChecked", "ariaSelected" };
    for (size_t a = 0; a < N_OF(PROP); a++) {
        for (const char *q = strstr(p, PROP[a]); q; q = strstr(q + 1, PROP[a])) {
            const char *ls = q;
            while (ls > p && ls[-1] != '\n') ls--;
            int k = 0;
            for (size_t i = 0; i < N_OF(TOGGLE_JS); i++)
                if (strncmp(ls, TOGGLE_JS[i], strlen(TOGGLE_JS[i])) == 0) k = 1;
            if (!k) fprintf(stderr, "  ARIA state set by an undecided line: %.70s\n", ls);
            WT_EQ(k, 1);
        }
    }
    WT_LACKS(p, "setAttribute(\"aria-");
    WT_LACKS(p, "setAttribute(\"role\"");
}

/* The body of the function whose first line is head: up to the next
 * line that closes a function at the same two-space indent. */
static char *body_of(const char *p, const char *head) {
    const char *a = strstr(p, head);
    const char *b = a ? strstr(a, "\n  }\n") : NULL;
    if (!a || !b) return NULL;
    char *out = malloc((size_t)(b - a) + 1);
    if (!out) return NULL;
    memcpy(out, a, (size_t)(b - a));
    out[b - a] = '\0';
    return out;
}
static int count_of(const char *s, const char *w) {
    int n = 0;
    for (const char *q = strstr(s, w); q; q = strstr(q + 1, w)) n++;
    return n;
}

/* A link shows what it names. The alerts view's every filter, search
 * and window are the defaults under an address that names any filter;
 * a kept type is the viewer's filter, never a drill-down; no drill-down
 * path keeps what the address set; each bar's "show all" clears the
 * view's filters; a scope in an address is applied, not kept. */
static void test_a_link_shows_what_it_names(void) {
    const char *p = (const char *)web_page;
    char *av = body_of(p, "  function alertsView() {");
    WT_ASSERT(av != NULL);
    if (av) {
        WT_HAS(av, "    $(\"al-q\").value = typeof VP.q === \"string\" ? VP.q : named ? \"\" : ctlKept(\"al-q\", \"\");");
        WT_HAS(av, "    $(\"al-win\").value = named ? ctlDefault(\"al-win\") : ctlKept(\"al-win\", ctlDefault(\"al-win\"));");
        WT_HAS(av, "    if (named && typeof VP.type !== \"string\") $(\"al-type\").value = \"\";");
        /* Every kept value read here is read only when the address
         * names no filter. */
        int lines = 0;
        for (const char *q = strstr(av, "ctlKept("); q; q = strstr(q + 1, "ctlKept(")) {
            const char *ls = q, *le = strchr(q, '\n');
            while (ls > av && ls[-1] != '\n') ls--;
            int ok = 0;
            for (const char *r = ls; r < (le ? le : q); r++) if (strncmp(r, "named ?", 7) == 0) ok = 1;
            if (!ok) fprintf(stderr, "  a kept value read under a named filter: %.70s\n", ls);
            WT_ASSERT(ok);
            lines++;
        }
        WT_ASSERT(lines >= 4);
        /* The drill-down is the address's: the kept type is not in it. */
        const char *d = strstr(av, "    ALP.drill = (");
        const char *e = d ? strstr(d, "      ? {") : NULL;
        WT_ASSERT(d != NULL && e != NULL);
        if (d && e) {
            int bad = 0;
            for (const char *q = strstr(d, "wantType"); q && q < e; q = strstr(q + 1, "wantType")) bad++;
            WT_EQ(bad, 0);
        }
        WT_HAS(av, "(typeof VP.type === \"string\" && VP.type)");
        /* A filter the address set is not kept. */
        WT_EQ(count_of(av, "ctlSave"), 0);
        WT_EQ(count_of(av, "prefSet"), 0);
        WT_EQ(count_of(av, "dispatchEvent"), 0);
        free(av);
    }
    char *dv = body_of(p, "  function devices() {");
    WT_ASSERT(dv != NULL);
    if (dv) {
        WT_EQ(count_of(dv, "ctlSave"), 0);
        WT_EQ(count_of(dv, "prefSet"), 0);
        WT_EQ(count_of(dv, "dispatchEvent"), 0);
        free(dv);
    }
    /* "show all": the view's filters to the page's defaults, forgotten. */
    WT_HAS(p, "    ids.forEach(function (id) { $(id).value = ctlDefault(id); prefSet(\"ctl.\" + id, null); });");
    WT_HAS(p, "  $(\"al-all\").addEventListener(\"click\", function () { showAll([\"al-state\", \"al-sev\", \"al-type\", \"al-q\", \"al-win\"]); });");
    WT_HAS(p, "  $(\"d-all\").addEventListener(\"click\", function () { showAll([\"d-q\"]); });");
    WT_HAS(p, "  $(\"n-all\").addEventListener(\"click\", function () { N.pick(\"\"); });");
    WT_HAS(p, "<a href=\"#alerts\" id=\"al-all\">show all</a>");
    WT_HAS(p, "<a href=\"#devices\" id=\"d-all\">show all</a>");
    WT_HAS(p, "<a href=\"#anomalies\" id=\"n-all\">show all</a>");
    /* A scope in an address applied, not kept; a viewer's pick kept. */
    WT_HAS(p, "    if (r && r.scope) setScope(r.scope, true);");
    WT_LACKS(p, "setScope(r.scope);");
    WT_HAS(p, "    if (!setScope(s)) return;");
}

/* The kind chip is the Anomalies list's own filter: the tile's
 * drill-down and the Overview's top five are every kind. */
static void test_the_chip_narrows_only_its_list(void) {
    const char *p = (const char *)web_page;
    char *an = body_of(p, "  function anomalies() {");
    WT_ASSERT(an != NULL);
    if (!an) return;
    WT_HAS(an, "    var kind = view === \"anomalies\" && !openOnly ? N.kind : \"\";");
    WT_HAS(an, "    if (kind) p += \"&kind=\" + encodeURIComponent(kind);");
    WT_HAS(an, "      if (kind) return;\n      var top = $(\"o-anoms\");");
    /* N.kind read once, in that line: nothing else here narrows by it. */
    WT_EQ(count_of(an, "N.kind"), 1);
    free(an);
}

/* What the page writes back and what it clears. A table writes only the
 * widths of the columns it has, so a gone column's (every query's
 * through the one "sql" id) does not pile up; the move from the build
 * before touches only that build's four keys, and "reset settings" only
 * this namespace, so a later build's slothweb.v2.* survives both. */
static void test_what_is_written_and_cleared(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "    Object.keys(t.w).forEach(function (k) { if (t.col(k)) w[k] = t.w[k]; });\n"
              "    if (Object.keys(w).length) v.w = w;");
    WT_LACKS(p, "v.w = t.w;");
    WT_HAS(p, "  var PREF_OLD = [\"slothweb.theme\", \"slothweb.scope\", \"slothweb.sensitivity\"];");
    WT_HAS(p, "        if (k && (PREF_OLD.indexOf(k) >= 0 || k.indexOf(\"slothweb.cols.\") === 0)) old.push(k);");
    WT_HAS(p, "        if (k && k.indexOf(PREF) === 0) ks.push(k);");
    WT_LACKS(p, "k.indexOf(PREF) !== 0");
    WT_LACKS(p, "if (k && k.indexOf(\"slothweb.\") === 0)");
    /* A kept alert type the server does not know is dropped and the list
     * asked again without it, once; a type the address names is shown
     * refused as before. Seen red with the drop removed. */
    WT_HAS(p, "    ALP.typeKept = typeof VP.type !== \"string\" && ALP.wantType !== \"\";");
    WT_HAS(p, "      if (ALP.typeKept && e.message === \"bad_type\") {\n"
              "        ALP.typeKept = false;\n"
              "        prefSet(\"ctl.al-type\", null);");
}

void run_prefs_tests(void) {
    WT_RUN(test_one_namespace_one_door);
    WT_RUN(test_tables_keep_widths_and_sort);
    WT_RUN(test_every_control_is_decided);
    WT_RUN(test_the_rest_and_the_address);
    WT_RUN(test_every_toggle_is_decided);
    WT_RUN(test_a_link_shows_what_it_names);
    WT_RUN(test_the_chip_narrows_only_its_list);
    WT_RUN(test_what_is_written_and_cleared);
}
