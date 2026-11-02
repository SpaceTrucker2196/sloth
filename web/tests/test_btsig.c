/* The Bluetooth SIG assigned numbers (web_btsig.h): the table this
 * binary was built with says which it is, the committed CSVs are the
 * ones web/data/btsig/SOURCE.md hashes, the lookups answer the SIG's
 * names for the values the BLE view shows, and nothing in the build
 * runs the refresh tool. Seen red with one hex digit of
 * company_identifiers.csv's hash in SOURCE.md changed, and with the
 * binary search's bound moved (0x0006 not found). */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "web_btsig.h"
#include "wtest.h"

#ifndef WEB_BTSIG_EXPECT
#define WEB_BTSIG_EXPECT NULL
#endif

static char *slurp_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    *len = 0;
    if (!f) return NULL;
    size_t cap = 1 << 18, n = 0;
    char *buf = malloc(cap + 1);
    while (buf) {
        n += fread(buf + n, 1, cap - n, f);
        if (n < cap) break;
        char *nb = realloc(buf, cap * 2 + 1);
        if (!nb) { free(buf); buf = NULL; break; }
        buf = nb;
        cap *= 2;
    }
    fclose(f);
    if (!buf) return NULL;
    buf[n] = '\0';
    *len = n;
    return buf;
}

static const char *const FILES[3] = { "company_identifiers", "service_uuids", "appearance_values" };

/* SOURCE.md's row for name.csv: its Rows and SHA-256 columns. */
static int source_row(const char *md, const char *name, long *rows, char sum[65]) {
    char key[48];
    snprintf(key, sizeof(key), "| `%s.csv` | ", name);
    const char *blk = strstr(md, "<!-- update-btsig:begin -->");
    const char *p = blk ? strstr(blk, key) : NULL;
    if (!p) return -1;
    p = strchr(p + strlen(key), '|');           /* past the table name */
    if (!p) return -1;
    char *e;
    *rows = strtol(p + 1, &e, 10);
    const char *q = strchr(e, '|');             /* past the rows */
    q = q ? strchr(q + 1, '|') : NULL;          /* past the bytes */
    q = q ? strchr(q, '`') : NULL;
    if (!q || strlen(q) < 66 || q[65] != '`') return -1;
    memcpy(sum, q + 1, 64);
    sum[64] = '\0';
    return 0;
}

static void test_builtin_table(void) {
    const web_btsig_tab_t *t = web_btsig_builtin();
    WT_ASSERT(t != NULL && t->source != NULL);
    if (!t || !t->source) return;
    const char *want = WEB_BTSIG_EXPECT;
    WT_ASSERT(want != NULL);
    if (want) {
        if (strcmp(t->source, want))
            fprintf(stderr, "  built with \"%s\", expected \"%s\"\n", t->source, want);
        WT_ASSERT(!strcmp(t->source, want));
    }
    /* Sorted, as the binary search needs. */
    for (size_t i = 1; i < t->ncompany; i++) WT_ASSERT(t->company[i - 1].value < t->company[i].value);
    for (size_t i = 1; i < t->nservice; i++) WT_ASSERT(t->service[i - 1].value < t->service[i].value);
    for (size_t i = 1; i < t->nappearance; i++) WT_ASSERT(t->appearance[i - 1].value < t->appearance[i].value);
    if (!strcmp(t->source, "none")) {
        WT_EQ(t->ncompany + t->nservice + t->nappearance, 0);
        WT_ASSERT(web_btsig_company(t, 0x004c) == NULL);
        return;
    }
    WT_ASSERT(t->ncompany > 3000);
    WT_ASSERT(t->nservice > 50);
    WT_ASSERT(t->nappearance > 200);
    /* The values the BLE view shows: a company, a service, an appearance;
     * the SIG's own id 0xFFFF is "internal use", not a registrant. */
    const char *s;
    WT_ASSERT((s = web_btsig_company(t, 0x004c)) && !strcmp(s, "Apple, Inc."));
    WT_ASSERT((s = web_btsig_company(t, 0x0006)) && !strcmp(s, "Microsoft"));
    WT_ASSERT((s = web_btsig_company(t, 0x00e0)) && !strcmp(s, "Google"));
    WT_ASSERT((s = web_btsig_company(t, 0x0000)) && strstr(s, "Ericsson"));
    WT_ASSERT((s = web_btsig_service(t, 0x180f)) && !strcmp(s, "Battery"));
    WT_ASSERT((s = web_btsig_service(t, 0x1812)) && !strcmp(s, "Human Interface Device"));
    WT_ASSERT((s = web_btsig_appearance(t, 0x03c1)) && !strcmp(s, "Human Interface Device / Keyboard"));
    WT_ASSERT((s = web_btsig_appearance(t, 0x0080)) && !strcmp(s, "Computer"));
    WT_ASSERT((s = web_btsig_appearance(t, 0x0000)) && !strcmp(s, "Unknown"));
    /* A miss, and the bounds. */
    WT_ASSERT(web_btsig_service(t, 0x0001) == NULL);
    WT_ASSERT(web_btsig_company(t, -1) == NULL);
    WT_ASSERT(web_btsig_company(t, 0x10000) == NULL);
    WT_ASSERT(web_btsig_appearance(t, 0x3fff) == NULL);
    /* Names: printable UTF-8, no control byte, within the cut. */
    for (size_t i = 0; i < t->nnames; i++) {
        const char *n = t->names[i];
        WT_ASSERT(strlen(n) <= WEB_BTSIG_NAME_MAX);
        for (const unsigned char *c = (const unsigned char *)n; *c; c++) WT_ASSERT(*c >= 0x20 && *c != 0x7f);
    }
}

/* web/data/btsig/ is the three files SOURCE.md names, byte for byte. */
static void test_committed_tables_match_source(void) {
    size_t len;
    char *md = slurp_file("web/data/btsig/SOURCE.md", &len);
    WT_ASSERT(md != NULL);
    if (!md) return;
    const web_btsig_tab_t *t = web_btsig_builtin();
    size_t counts[3] = { t->ncompany, t->nservice, t->nappearance };
    for (int i = 0; i < 3; i++) {
        long rows = -1;
        char want[65] = "";
        WT_EQ(source_row(md, FILES[i], &rows, want), 0);
        char p[80];
        snprintf(p, sizeof(p), "web/data/btsig/%s.csv", FILES[i]);
        size_t n = 0;
        char *csv = slurp_file(p, &n);
        WT_ASSERT(csv != NULL);
        if (!csv) continue;
        uint8_t d[32];
        web_sha256(csv, n, d);
        char got[65];
        for (int k = 0; k < 32; k++) snprintf(got + 2 * k, 3, "%02x", d[k]);
        if (strcmp(got, want))
            fprintf(stderr, "  %s: sha256 %s, SOURCE.md says %s\n", p, got, want);
        WT_ASSERT(!strcmp(got, want));
        WT_ASSERT(rows > 50);
        /* The header, then one row per line. */
        WT_ASSERT(!strncmp(csv, "value,name\n", 11));
        long lines = 0;
        for (const char *c = csv; *c; c++) lines += *c == '\n';
        WT_EQ(lines - 1, rows);
        /* The built table holds every distinct value of the committed
         * file (a duplicate keeps the first). */
        if (!strcmp(t->source, "sig")) WT_ASSERT((long)counts[i] <= rows && (long)counts[i] >= rows - 8);
        free(csv);
    }
    free(md);
}

/* The refresh is a developer's step, never a build's: the Makefile runs
 * update_btsig.sh only from the update-btsig target, and no workflow
 * names it. */
static void test_update_btsig_is_never_automatic(void) {
    size_t len;
    char *mk = slurp_file("Makefile", &len);
    WT_ASSERT(mk != NULL);
    if (!mk) return;
    int runs = 0, in_target = 0;
    for (const char *p = strstr(mk, "update_btsig.sh"); p; p = strstr(p + 1, "update_btsig.sh")) {
        const char *ls = p;
        while (ls > mk && ls[-1] != '\n') ls--;
        if (ls[0] == '#') continue;                 /* a comment */
        runs++;
        /* The recipe line of update-btsig: a tab, under the target. */
        const char *prev = ls > mk ? ls - 1 : ls;
        while (prev > mk && prev[-1] != '\n') prev--;
        if (ls[0] == '\t' && !strncmp(prev, "update-btsig:", 13)) in_target++;
    }
    WT_EQ(runs, 1);
    WT_EQ(in_target, 1);
    WT_HAS(mk, "update-btsig:\n\tsh web/tools/update_btsig.sh web/data/btsig $(SRC)\n");
    free(mk);
    static const char *const wf[] = { ".github/workflows/ci.yml", ".github/workflows/wiki-sync.yml" };
    for (size_t i = 0; i < sizeof(wf) / sizeof(wf[0]); i++) {
        char *y = slurp_file(wf[i], &len);
        if (!y) continue;
        WT_LACKS(y, "update_btsig");
        WT_LACKS(y, "update-btsig");
        free(y);
    }
}

void run_btsig_tests(void) {
    WT_RUN(test_builtin_table);
    WT_RUN(test_committed_tables_match_source);
    WT_RUN(test_update_btsig_is_never_automatic);
}
