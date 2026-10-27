/* The alert knowledge table (web_alertkb.h) held to the files it is
 * generated from, read again here: every row of include/sloth_alerts.def
 * has an entry, in order, with its technique; every entry has what the
 * detail page's sections need (a trigger, sources, steps); every type
 * has a section in docs/wiki/alert-remediation.md; and every source a
 * remediation section names is a corpus document whose alert_kinds list
 * that type, so no step rests on a source the corpus does not cite for
 * it. The two own-operational-state types have no corpus document by
 * design (agents/AGENTS.md) and may cite sloth's own pages only. Runs
 * from the top of the tree, as the suite does. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "web_alertkb.h"
#include "wtest.h"

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 1 << 16, n = 0, r;
    char *b = malloc(cap + 1);
    while (b && (r = fread(b + n, 1, cap - n, f)) > 0) {
        n += r;
        if (n == cap) {
            char *nb = realloc(b, cap * 2 + 1);
            if (!nb) { free(b); b = NULL; break; }
            b = nb;
            cap *= 2;
        }
    }
    fclose(f);
    if (b) b[n] = '\0';
    return b;
}

static int own_state(const char *name) {
    return !strcmp(name, "NO_MONITOR_MODE") || !strcmp(name, "BT_OWN_TRANSMIT");
}

/* Seen red with the generator's row_label() mapping removed
 * (MY_NETWORK_RECON's trigger went empty). */
static void test_every_type_has_an_entry(void) {
    char *def = slurp("include/sloth_alerts.def");
    WT_ASSERT(def != NULL);
    if (!def) return;
    int n = 0;
    for (char *p = def; p; ) {
        if (!strncmp(p, "X(", 2)) {
            const char *a = p + 2, *c = strchr(a, ',');
            const char *q1 = c ? strchr(c, '"') : NULL;
            const char *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
            WT_ASSERT(c && q2);
            if (c && q2 && n < web_akb_n) {
                const web_akb_t *k = &web_akb[n];
                int same = strlen(k->name) == (size_t)(c - a) &&
                           !strncmp(k->name, a, (size_t)(c - a));
                if (!same) fprintf(stderr, "    entry %d is %s, the .def says %.*s\n",
                                   n, k->name, (int)(c - a), a);
                WT_ASSERT(same);
                WT_ASSERT(strlen(k->technique) == (size_t)(q2 - q1 - 1) &&
                          !strncmp(k->technique, q1 + 1, (size_t)(q2 - q1 - 1)));
            }
            n++;
        }
        char *nl = strchr(p, '\n');
        p = nl ? nl + 1 : NULL;
    }
    free(def);
    WT_EQ(web_akb_n, n);
    WT_ASSERT(n >= 90);
    for (int t = 0; t < web_akb_n; t++) {
        const web_akb_t *k = &web_akb[t];
        int ok = k->sev[0] && k->what[0] && k->ninvestigate >= 1 &&
                 k->nfix >= 1 && k->vendor_fix[0] && k->nfix_src >= 1 &&
                 (k->nsrc >= 1 || own_state(k->name));
        if (!ok)
            fprintf(stderr, "    %s: sev \"%s\" what %zu B, %d sources, %d investigate,"
                    " %d fix, vendor fix %zu B, %d fix sources\n", k->name, k->sev,
                    strlen(k->what), k->nsrc, k->ninvestigate, k->nfix,
                    strlen(k->vendor_fix), k->nfix_src);
        WT_ASSERT(ok);
        for (int i = 0; i < k->nsrc; i++) {
            WT_ASSERT(k->src[i].path[0] && k->src[i].citation[0]);
            WT_ASSERT(!strncmp(k->src[i].url, "http", 4));
            WT_ASSERT(k->src[i].lead[0]);
        }
        WT_EQ(web_akb_find(k->name), t);
        WT_ASSERT(web_akb_get(t) == k);
    }
    WT_ASSERT(web_akb_get(-1) == NULL);
    WT_ASSERT(web_akb_get(web_akb_n) == NULL);
    WT_EQ(web_akb_find("NOT_A_TYPE"), -1);
}

/* The text is the files' words, reduced to plain text: no link, code
 * or emphasis markup reaches the page, except the code spans the whole
 * trigger keeps for the page to set as code, which pair up. Seen red
 * with plain()'s link branch removed from the generator. */
static void test_text_is_plain(void) {
    for (int t = 0; t < web_akb_n; t++) {
        const web_akb_t *k = &web_akb[t];
        const char *const parts[] = { k->summary, k->what, k->match, k->context, k->vendor_fix };
        for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
            WT_ASSERT(!strstr(parts[i], "]("));
            WT_ASSERT(!strstr(parts[i], "**"));
            if (parts[i] != k->what) WT_ASSERT(!strchr(parts[i], '`'));
        }
        int ticks = 0;
        for (const char *p = k->what; *p; p++) ticks += *p == '`';
        if (ticks % 2) fprintf(stderr, "    %s: an unpaired code mark\n", k->name);
        WT_EQ(ticks % 2, 0);
        for (int i = 0; i < k->ninvestigate; i++) WT_ASSERT(!strchr(k->investigate[i], '`'));
        for (int i = 0; i < k->nfix; i++) WT_ASSERT(!strchr(k->fix[i], '`'));
    }
    /* Spot checks against the rule table and the corpus, by content. */
    int ps = web_akb_find("PORT_SCAN");
    WT_ASSERT(ps >= 0);
    if (ps >= 0) {
        WT_HAS(web_akb[ps].what, "distinct local ports");
        WT_ASSERT(web_akb[ps].nsrc >= 1 && !strcmp(web_akb[ps].src[0].path, "research/mitre/T1595.md"));
    }
    int ka = web_akb_find("KARMA_AP");
    WT_ASSERT(ka >= 0);
    if (ka >= 0) WT_HAS(web_akb[ka].what, "(`, N in client PNLs`)");
    int my = web_akb_find("MY_NETWORK_RECON");
    WT_ASSERT(my >= 0 && web_akb[my].what[0]);
}

/* What the page leads with is one sentence, short, with no issue
 * reference: the rule table's cells run to a thousand bytes of
 * engineering history, which the page keeps under "details". Seen red
 * with summarise() copying the cell as it stands, cut to the cap (its
 * issue references kept), restored by the inverse edit. */
static void test_summary_is_short(void) {
    int over = 0;
    for (int t = 0; t < web_akb_n; t++) {
        const web_akb_t *k = &web_akb[t];
        size_t n = strlen(k->summary);
        if (n == 0 || n > WEB_AKB_SUMMARY_MAX || strstr(k->summary, "(#")) {
            fprintf(stderr, "    %s: summary %zu B: %.60s\n", k->name, n, k->summary);
            over++;
        }
    }
    WT_EQ(over, 0);
    int ps = web_akb_find("PORT_SCAN");
    if (ps >= 0) WT_HAS(web_akb[ps].summary, "one source touched");
    int tpc = web_akb_find("TPC_ABSENT_HIGH_BAND");
    if (tpc >= 0) WT_LACKS(web_akb[tpc].summary, "#101");
}

/* Does the rule table's Sev cell name word (LOW, WARN, CRIT) whole? */
static int cell_names(const char *cell, const char *word) {
    size_t n = strlen(word);
    for (const char *p = cell; (p = strstr(p, word)) != NULL; p += n) {
        int before = p == cell || !((p[-1] >= 'A' && p[-1] <= 'Z') || p[-1] == '_');
        int after = !((p[n] >= 'A' && p[n] <= 'Z') || p[n] == '_');
        if (before && after) return 1;
    }
    return 0;
}

/* Every severity a rule can fire at is one its rule-table row names: the
 * ALERT_SEV_* literals in the severity argument of each fire*() call in
 * src/alerts/, against the Sev cell the alert's page shows as "the
 * rule's". A severity computed at run time (a variable) names no literal
 * and is passed over; the count of those is printed. Seen red with
 * SSH_BRUTE_FORCE's row put back to WARN (the six brute-force rows said
 * WARN while every fire() of theirs passed ALERT_SEV_CRIT). */
static void test_rule_severity_matches_the_code(void) {
    static const char *const files[] = {
        "src/alerts/rules_ble.c", "src/alerts/rules_camera.c", "src/alerts/rules_enterprise.c",
        "src/alerts/rules_mle.c", "src/alerts/rules_regulatory.c", "src/alerts/rules_twin.c",
        "src/alerts/rules_wifi_mgmt.c", "src/alerts/rules_wired.c",
    };
    static const char *const W[] = { "LOW", "WARN", "CRIT" };
    int sites = 0, computed = 0;
    for (size_t f = 0; f < sizeof(files) / sizeof(files[0]); f++) {
        char *src = slurp(files[f]);
        WT_ASSERT(src != NULL);
        if (!src) continue;
        for (char *p = src; (p = strstr(p, "fire")) != NULL; p++) {
            if (p > src && ((p[-1] >= 'a' && p[-1] <= 'z') || p[-1] == '_')) continue;
            char *q = p + 4;
            while ((*q >= 'a' && *q <= 'z') || *q == '_') q++;
            if (strncmp(q, "(ALERT_TYPE_", 12) != 0) continue;
            char name[96];
            const char *a = q + 12, *e = a;
            while ((*e >= 'A' && *e <= 'Z') || (*e >= '0' && *e <= '9') || *e == '_') e++;
            if (*e != ',' || (size_t)(e - a) >= sizeof(name)) continue;
            snprintf(name, sizeof(name), "%.*s", (int)(e - a), a);
            /* The second argument: to the next comma at depth 0. */
            const char *b = e + 1;
            int depth = 0;
            const char *z = b;
            for (; *z && !(depth == 0 && (*z == ',' || *z == ')')); z++) {
                if (*z == '(') depth++;
                if (*z == ')') depth--;
            }
            char arg[256];
            snprintf(arg, sizeof(arg), "%.*s", (int)(z - b < 255 ? z - b : 255), b);
            int t = web_akb_find(name);
            WT_ASSERT(t >= 0);
            if (t < 0) continue;
            int lits = 0;
            for (int k = 0; k < 3; k++) {
                char lit[24];
                snprintf(lit, sizeof(lit), "ALERT_SEV_%s", W[k]);
                if (!strstr(arg, lit)) continue;
                lits++;
                int ok = cell_names(web_akb[t].sev, W[k]);
                if (!ok) fprintf(stderr, "    %s fires %s (%s) but its row says \"%s\"\n",
                                 name, W[k], files[f], web_akb[t].sev);
                WT_ASSERT(ok);
            }
            if (lits) sites++; else computed++;
        }
        free(src);
    }
    fprintf(stderr, "    %d fire sites with a literal severity checked, %d computed\n",
            sites, computed);
    WT_ASSERT(sites >= 70);
}

/* The frontmatter alert_kinds of a corpus document lists the type. */
static int doc_cites(const char *path, const char *name) {
    char *t = slurp(path);
    if (!t) return 0;
    const char *a = strstr(t, "\nalert_kinds:");
    const char *e = a ? strchr(a + 1, '\n') : NULL;
    char want[96];
    snprintf(want, sizeof(want), "ALERT_TYPE_%s", name);
    int hit = 0;
    for (const char *p = a; p && e && (p = strstr(p, want)) != NULL && p < e; p++) {
        char after = p[strlen(want)];
        if (after == ',' || after == ']' || after == ' ') { hit = 1; break; }
    }
    free(t);
    return hit;
}

/* Seen red with SMB1_USE's section citing research/mitre/T1110.md as
 * well (that document does not list SMB1_USE; the page restored by the
 * inverse edit). */
static void test_remediation_rests_on_the_corpus(void) {
    for (int t = 0; t < web_akb_n; t++) {
        const web_akb_t *k = &web_akb[t];
        int corpus = 0;
        for (int i = 0; i < k->nfix_src; i++) {
            const char *p = k->fix_src[i];
            struct stat sb;
            int exists = stat(p, &sb) == 0;
            if (!exists) fprintf(stderr, "    %s cites %s, which is not there\n", k->name, p);
            WT_ASSERT(exists);
            if (!strncmp(p, "research/", 9)) {
                int ok = doc_cites(p, k->name);
                if (!ok) fprintf(stderr, "    %s cites %s, whose alert_kinds do not list it\n",
                                 k->name, p);
                WT_ASSERT(ok);
                corpus++;
                /* and it is one of the entry's own sources */
                int listed = 0;
                for (int j = 0; j < k->nsrc; j++) listed |= !strcmp(k->src[j].path, p);
                WT_ASSERT(listed);
            } else {
                /* sloth's own pages, for the own-state types only */
                WT_ASSERT(own_state(k->name));
                WT_ASSERT(!strncmp(p, "docs/", 5));
            }
        }
        if (!own_state(k->name) && !corpus)
            fprintf(stderr, "    %s: no corpus source in its remediation\n", k->name);
        WT_ASSERT(own_state(k->name) || corpus >= 1);
    }
}

/* Every section heading of the page names a type, once. */
static void test_remediation_page_names_every_type(void) {
    char *md = slurp("docs/wiki/alert-remediation.md");
    WT_ASSERT(md != NULL);
    if (!md) return;
    int seen[256] = { 0 }, n = 0;
    for (const char *p = strstr(md, "\n## `"); p; p = strstr(p + 1, "\n## `")) {
        const char *a = p + 5, *e = strchr(a, '`');
        if (!e) break;
        char name[96];
        snprintf(name, sizeof(name), "%.*s", (int)(e - a), a);
        int t = web_akb_find(name);
        if (t < 0) fprintf(stderr, "    a section for %s, not a type\n", name);
        WT_ASSERT(t >= 0);
        if (t >= 0 && t < 256) { WT_EQ(seen[t], 0); seen[t]++; }
        n++;
    }
    WT_EQ(n, web_akb_n);
    WT_HAS(md, "**Summary**");
    WT_HAS(md, "**Sources**");
    WT_HAS(md, "**Last updated**");
    WT_HAS(md, "\n## Related pages\n");
    free(md);
    char *idx = slurp("docs/wiki/index.md");
    WT_HAS(idx, "[[alert-remediation]]");
    free(idx);
}

void run_alertkb_tests(void) {
    WT_RUN(test_every_type_has_an_entry);
    WT_RUN(test_text_is_plain);
    WT_RUN(test_summary_is_short);
    WT_RUN(test_rule_severity_matches_the_code);
    WT_RUN(test_remediation_rests_on_the_corpus);
    WT_RUN(test_remediation_page_names_every_type);
}
