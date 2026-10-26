/* The vendor table (#162, M4): web/tools/oui_csv.c run on registry CSVs
 * this test writes into a fresh directory, the generated C text, and
 * web_oui.c's lookup over what the builder made. The rows are built
 * the way the IEEE registry files are laid out (Registry, Assignment,
 * Organization Name, Organization Address; RFC 4180 quoting). Since the
 * registry CSVs are committed (owner ruling 2026-10-26) the builder is
 * also run on web/data/ itself, under a time bound, and the files are
 * held to web/data/SOURCE.md's hashes. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "oui_csv.h"
#include "sha256.h"
#include "web_oui.h"
#include "wtest.h"

/* The table `make web-test` says this build should have: "ieee" when
 * WEB_OUI_DIR held the CSVs, "sloth" when it did not. */
#ifndef WEB_OUI_EXPECT
#define WEB_OUI_EXPECT NULL
#endif

static char g_dir[64];

static void path_in(char *out, size_t sz, const char *name) {
    snprintf(out, sz, "%s/%s", g_dir, name);
}

static void write_file(const char *name, const char *text) {
    char p[128];
    path_in(p, sizeof(p), name);
    FILE *f = fopen(p, "wb");
    WT_ASSERT(f != NULL);
    if (!f) return;
    fputs(text, f);
    fclose(f);
}

static const char OUI_CSV[] =
    "\xef\xbb\xbfRegistry,Assignment,Organization Name,Organization Address\r\n"
    "MA-L,000393,\"Apple, Inc.\",1 Infinite Loop Cupertino CA US 95014\r\n"
    "MA-L,70B3D5,IEEE Registration Authority,445 Hoes Lane Piscataway NJ US 08554\r\n"
    "MA-L,002272,American Micro-Fuel Device Corp.,\"2181 Buchanan Loop,\nFerndale WA US\"\r\n"
    "MA-L,F8E43B,Private,\r\n"
    "MA-L,acde48,\"Quote \"\"Q\"\" \\Back */\",x\r\n"
    "MA-L,000393,Apple Again,later duplicate\r\n";
static const char MAM_CSV[] =
    "Registry,Assignment,Organization Name,Organization Address\n"
    "MA-M,70B3D51,Tiny Sensors GmbH,Berlin DE\n";
static const char MAS_CSV[] =
    "Registry,Assignment,Organization Name,Organization Address\n"
    "MA-S,70B3D5F2A,Small Vendor Ltd,Leeds GB\n"
    "CID,0A1B2C,A CID owner,locally administered by definition\n"
    "IAB,0050C2001,An IAB Holder,x\n";

static oui_build_t B;

static int build(void) {
    char p[3][128];
    path_in(p[0], sizeof(p[0]), "oui.csv");
    path_in(p[1], sizeof(p[1]), "mam.csv");
    path_in(p[2], sizeof(p[2]), "oui36.csv");
    oui_build_init(&B);
    for (int i = 0; i < 3; i++)
        if (oui_build_csv(&B, p[i]) != 0) {
            fprintf(stderr, "  %s\n", B.err);
            return -1;
        }
    return oui_build_finish(&B, "ieee");
}

static void mac(uint8_t m[6], unsigned a, unsigned b, unsigned c, unsigned d,
                unsigned e, unsigned f) {
    m[0] = (uint8_t)a; m[1] = (uint8_t)b; m[2] = (uint8_t)c;
    m[3] = (uint8_t)d; m[4] = (uint8_t)e; m[5] = (uint8_t)f;
}

/* Each registry's block, the most specific first: an MA-S and an MA-M
 * block inside the IEEE's own MA-L assignment resolve to their holders,
 * the rest of that MA-L to the IEEE. */
static void test_lookup_by_block(void) {
    WT_EQ(build(), 0);
    WT_EQ(B.counts[WEB_OUI_MAL], 5);
    WT_EQ(B.counts[WEB_OUI_MAM], 1);
    WT_EQ(B.counts[WEB_OUI_MAS], 2);            /* the MA-S and the IAB */
    WT_EQ(B.skipped, 1);                        /* the CID row */
    WT_EQ(B.duplicates, 1);
    WT_ASSERT(web_oui_full(&B.tab));
    uint8_t m[6];
    web_oui_hit_t h;

    mac(m, 0x00, 0x03, 0x93, 0x12, 0x34, 0x56);
    WT_EQ(web_oui_lookup(&B.tab, m, &h), 1);
    WT_ASSERT(!strcmp(h.name, "Apple, Inc."));  /* the first row kept */
    WT_EQ(h.bits, 24);
    WT_EQ(h.cls, WEB_OUI_MAL);
    WT_ASSERT(!strcmp(h.block, "00:03:93"));
    WT_EQ(h.local, 0);
    WT_EQ(h.multicast, 0);

    mac(m, 0x70, 0xb3, 0xd5, 0xf2, 0xa1, 0x23);
    WT_EQ(web_oui_lookup(&B.tab, m, &h), 1);
    WT_ASSERT(!strcmp(h.name, "Small Vendor Ltd"));
    WT_EQ(h.bits, 36);
    WT_ASSERT(!strcmp(h.block, "70:b3:d5:f2:a"));

    mac(m, 0x70, 0xb3, 0xd5, 0x1f, 0xff, 0xff);
    WT_EQ(web_oui_lookup(&B.tab, m, &h), 1);
    WT_ASSERT(!strcmp(h.name, "Tiny Sensors GmbH"));
    WT_EQ(h.bits, 28);
    WT_ASSERT(!strcmp(h.block, "70:b3:d5:1"));

    /* Just past the MA-S block: the MA-L holder, the IEEE. */
    mac(m, 0x70, 0xb3, 0xd5, 0xf2, 0xb0, 0x00);
    WT_EQ(web_oui_lookup(&B.tab, m, &h), 1);
    WT_ASSERT(!strcmp(h.name, "IEEE Registration Authority"));
    WT_EQ(h.bits, 24);

    mac(m, 0x00, 0x50, 0xc2, 0x00, 0x1a, 0xbc);
    WT_EQ(web_oui_lookup(&B.tab, m, &h), 1);
    WT_ASSERT(!strcmp(h.name, "An IAB Holder"));
    WT_EQ(h.bits, 36);

    mac(m, 0xf8, 0xe4, 0x3b, 0, 0, 1);
    WT_EQ(web_oui_lookup(&B.tab, m, &h), 1);
    WT_EQ(h.private_, 1);

    /* A quoted field with a quote in it, a comma in the next field and
     * a line break inside a quoted address. */
    mac(m, 0xac, 0xde, 0x48, 0, 0, 1);
    WT_EQ(web_oui_lookup(&B.tab, m, &h), 1);
    WT_ASSERT(!strcmp(h.name, "Quote \"Q\" \\Back */"));
    mac(m, 0x00, 0x22, 0x72, 0, 0, 1);
    WT_EQ(web_oui_lookup(&B.tab, m, &h), 1);
    WT_ASSERT(!strcmp(h.name, "American Micro-Fuel Device Corp."));
}

/* A miss says only that: the bits are reported whatever the table has.
 * The CID row was skipped, so its prefix is a miss too. */
static void test_misses_and_bits(void) {
    uint8_t m[6];
    web_oui_hit_t h;
    mac(m, 0x02, 0x03, 0x93, 0x12, 0x34, 0x56);   /* Apple's, LA bit set */
    WT_EQ(web_oui_lookup(&B.tab, m, &h), 0);
    WT_EQ(h.found, 0);
    WT_EQ(h.local, 1);
    WT_EQ(h.multicast, 0);
    WT_EQ(h.bits, 0);
    mac(m, 0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb);
    WT_EQ(web_oui_lookup(&B.tab, m, &h), 0);
    WT_EQ(h.multicast, 1);
    WT_EQ(h.local, 0);
    mac(m, 0x0a, 0x1b, 0x2c, 0, 0, 1);
    WT_EQ(web_oui_lookup(&B.tab, m, &h), 0);
    WT_EQ(h.local, 1);
    mac(m, 0x00, 0x03, 0x94, 0, 0, 1);            /* the neighbour of Apple's */
    WT_EQ(web_oui_lookup(&B.tab, m, &h), 0);
    WT_EQ(web_oui_lookup(NULL, m, &h), 0);
    uint8_t b[6];
    WT_EQ(web_oui_mac_bytes("70:b3:d5:f2:a1:23", b), 0);
    WT_EQ(b[3], 0xf2);
    WT_EQ(web_oui_mac_bytes("70:B3:d5:f2:a1:23", b), -1);   /* not canonical */
    WT_EQ(web_oui_mac_bytes("70-b3-d5-f2-a1-23", b), -1);
    WT_EQ(web_oui_mac_bytes("70:b3:d5:f2:a1", b), -1);
}

/* The generated C: the table's own symbol, and every name a string
 * literal that no registry byte can end or turn into a comment, a
 * trigraph or a line splice. Seen red with '"', '*' and '/' passed
 * through unescaped. */
static void test_emit(void) {
    char p[128];
    path_in(p, sizeof(p), "table.c");
    FILE *f = fopen(p, "w");
    WT_ASSERT(f != NULL);
    if (!f) return;
    WT_EQ(oui_build_emit(&B, f), 0);
    fclose(f);
    static char buf[1 << 16];
    f = fopen(p, "rb");
    size_t n = f ? fread(buf, 1, sizeof(buf) - 1, f) : 0;
    if (f) fclose(f);
    buf[n] = '\0';
    WT_HAS(buf, "const web_oui_tab_t web_oui_generated = {");
    WT_HAS(buf, "\"Apple, Inc.\",");
    WT_HAS(buf, "\"Quote \\042Q\\042 \\134Back \\052\\057\",");
    WT_HAS(buf, "\"ieee\", { 5, 1, 2 }");
    WT_LACKS(buf, "\"Q\"");
    WT_LACKS(buf, "*/\"");
    unlink(p);
}

/* A malformed registry fails the build, naming the row. Seen red with
 * parse_hex()'s length check removed. */
static void test_bad_csv_fails(void) {
    static const char *const bad[][2] = {
        { "Registry,Assignment,Organization Name\nMA-L,0003,Short\n", "hex length" },
        { "Registry,Assignment,Organization Name\nMA-M,000393,Wrong length\n", "hex length" },
        { "Registry,Assignment,Organization Name\nMA-L,00039G,Not hex\n", "hex length" },
        { "Registry,Assignment,Organization Name\nMA-L,000393,\"Unterminated\n", "unterminated" },
        { "Registry,Assignment,Organization Name\nMA-L,000393\n", "hex length" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        write_file("bad.csv", bad[i][0]);
        char p[128];
        path_in(p, sizeof(p), "bad.csv");
        oui_build_t b;
        oui_build_init(&b);
        WT_EQ(oui_build_csv(&b, p), -1);
        WT_HAS(b.err, bad[i][1]);
        oui_build_free(&b);
        unlink(p);
    }
    /* A field past 4 KiB. */
    char *big = malloc(OUI_CSV_FIELD_MAX + 64);
    WT_ASSERT(big != NULL);
    if (!big) return;
    strcpy(big, "MA-L,000393,");
    size_t o = strlen(big);
    memset(big + o, 'a', OUI_CSV_FIELD_MAX + 1);
    big[o + OUI_CSV_FIELD_MAX + 1] = '\0';
    write_file("big.csv", big);
    free(big);
    char p[128];
    path_in(p, sizeof(p), "big.csv");
    oui_build_t b;
    oui_build_init(&b);
    WT_EQ(oui_build_csv(&b, p), -1);
    WT_HAS(b.err, "4 KiB");
    oui_build_free(&b);
    unlink(p);
    oui_build_init(&b);
    WT_EQ(oui_build_csv(&b, "/nonexistent/oui.csv"), -1);
    oui_build_free(&b);
}

/* A name is cut on a code-point boundary and cleaned: a control byte
 * and a byte that starts no well-formed sequence become '?'. */
static void test_names_cleaned(void) {
    char row[512];
    snprintf(row, sizeof(row),
             "MA-L,111111,\"  Tab\tand \xff bad \xe2\x82\xac euro  \",x\n"
             "MA-L,222222,%s\xc3\xa9tail,x\n",
             "0123456789012345678901234567890123456789012345678901234567890");
    write_file("names.csv", row);
    char p[128];
    path_in(p, sizeof(p), "names.csv");
    oui_build_t b;
    oui_build_init(&b);
    WT_EQ(oui_build_csv(&b, p), 0);
    WT_EQ(oui_build_finish(&b, "ieee"), 0);
    uint8_t m[6];
    web_oui_hit_t h;
    mac(m, 0x11, 0x11, 0x11, 0, 0, 1);
    WT_EQ(web_oui_lookup(&b.tab, m, &h), 1);
    WT_ASSERT(!strcmp(h.name, "Tab?and ? bad \xe2\x82\xac euro"));
    mac(m, 0x22, 0x22, 0x22, 0, 0, 1);
    WT_EQ(web_oui_lookup(&b.tab, m, &h), 1);
    /* 61 digits and a two-byte é would be 63: it fits; the next byte
     * would not, and the cut never splits the é. */
    WT_EQ(strlen(h.name), 63);
    WT_ASSERT(!strcmp(h.name + 61, "\xc3\xa9"));
    oui_build_free(&b);
    unlink(p);
}

/* No CSV: sloth's own table, read out of src/oui.c as text, every
 * initialiser line of it. */
static void test_sloth_fallback(void) {
    FILE *f = fopen("src/oui.c", "rb");
    WT_ASSERT(f != NULL);
    if (!f) return;
    static char buf[1 << 16];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    int lines = 0;
    for (const char *q = buf; (q = strstr(q, "{ 0x")); q++) lines++;
    WT_ASSERT(lines > 100);
    oui_build_t b;
    oui_build_init(&b);
    WT_EQ(oui_build_sloth(&b, "src/oui.c"), 0);
    WT_EQ(oui_build_finish(&b, "sloth"), 0);
    WT_EQ((long long)b.n, lines);
    WT_ASSERT(!web_oui_full(&b.tab));
    uint8_t m[6];
    web_oui_hit_t h;
    mac(m, 0x00, 0x03, 0x93, 1, 2, 3);
    WT_EQ(web_oui_lookup(&b.tab, m, &h), 1);
    WT_ASSERT(!strcmp(h.name, "Apple"));
    /* An MA-S vendor that sloth's 117 entries miss. */
    mac(m, 0x70, 0xb3, 0xd5, 0xf2, 0xa1, 0x23);
    WT_EQ(web_oui_lookup(&b.tab, m, &h), 0);
    oui_build_free(&b);
}

/* The table this binary was built with says which it is, and one built
 * without the CSVs is never "full". */
static void test_builtin_table(void) {
    const web_oui_tab_t *t = web_oui_builtin();
    WT_ASSERT(t != NULL && t->source != NULL);
    if (!t || !t->source) return;
    WT_ASSERT(!strcmp(t->source, "ieee") || !strcmp(t->source, "sloth") ||
              !strcmp(t->source, "none"));
    /* Not "whichever it is": the default build has web/data/ and must
     * be the IEEE table, a WEB_OUI_DIR without CSVs must fall back.
     * Seen red with WEB_OUI_EXPECT's two branches swapped. */
    const char *want = WEB_OUI_EXPECT;
    WT_ASSERT(want != NULL);
    if (want) {
        WT_ASSERT(!strcmp(t->source, want));
        if (strcmp(t->source, want))
            fprintf(stderr, "  built with \"%s\", expected \"%s\"\n",
                    t->source, want);
    }
    if (!strcmp(t->source, "sloth")) {
        WT_ASSERT(!web_oui_full(t));
        WT_EQ(t->counts[WEB_OUI_MAM] + t->counts[WEB_OUI_MAS], 0);
        WT_ASSERT(t->counts[WEB_OUI_MAL] > 100);
    }
    if (!strcmp(t->source, "ieee")) WT_ASSERT(web_oui_full(t));
    /* Sorted, as the binary search needs. */
    for (size_t i = 1; i < t->n; i++) WT_ASSERT(t->e[i - 1].key < t->e[i].key);
}

/* ── the committed registry ──────────────────────────────────────────── */

static const char *const REG_FILES[4] = { "oui", "mam", "oui36", "iab" };

typedef struct {
    int           rc;
    unsigned      counts[WEB_OUI_CLASSES];
    unsigned long duplicates, skipped;
    size_t        n, nnames;
    long          probe;        /* set by a builder that checks a lookup */
} bounded_t;

/* fn(dir, out) in a child that SIGALRM ends after secs, so a builder
 * that never terminates fails this test instead of hanging the suite.
 * 0 with *out filled, or -1 (the child hung, crashed or failed). */
static int run_bounded(void (*fn)(const char *, bounded_t *), const char *dir,
                       unsigned secs, bounded_t *out) {
    int fd[2];
    memset(out, 0, sizeof(*out));
    out->rc = -1;
    if (pipe(fd) != 0) return -1;
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) { close(fd[0]); close(fd[1]); return -1; }
    if (pid == 0) {
        close(fd[0]);
        alarm(secs);
        bounded_t r;
        memset(&r, 0, sizeof(r));
        fn(dir, &r);
        ssize_t w = write(fd[1], &r, sizeof(r));
        _exit(w == (ssize_t)sizeof(r) ? 0 : 1);
    }
    close(fd[1]);
    bounded_t r;
    size_t got = 0;
    while (got < sizeof(r)) {
        ssize_t k = read(fd[0], (char *)&r + got, sizeof(r) - got);
        if (k <= 0) break;
        got += (size_t)k;
    }
    close(fd[0]);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {}
    if (WIFSIGNALED(st)) {
        fprintf(stderr, "  the builder %s (bound %u s)\n",
                WTERMSIG(st) == SIGALRM ? "had not finished" : "crashed", secs);
        return -1;
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0 || got != sizeof(r)) return -1;
    *out = r;
    return 0;
}

static void fill(const oui_build_t *b, bounded_t *r) {
    memcpy(r->counts, b->counts, sizeof(r->counts));
    r->duplicates = b->duplicates;
    r->skipped = b->skipped;
    r->n = b->n;
    r->nnames = b->nnames;
}

static void build_committed(const char *dir, bounded_t *r) {
    static oui_build_t b;
    oui_build_init(&b);
    r->rc = 0;
    for (int i = 0; i < 4 && r->rc == 0; i++) {
        char p[256];
        snprintf(p, sizeof(p), "%s/%s.csv", dir, REG_FILES[i]);
        if (oui_build_csv(&b, p) != 0) {
            fprintf(stderr, "  %s\n", b.err);
            r->rc = -1;
        }
    }
    if (r->rc == 0) r->rc = oui_build_finish(&b, "ieee");
    fill(&b, r);
    oui_build_free(&b);
}

static char *slurp_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    *len = 0;
    if (!f) return NULL;
    size_t cap = 1 << 20, n = 0;
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

/* SOURCE.md's row for name.csv: its Rows and SHA-256 columns. */
static int source_row(const char *md, const char *name, long *rows,
                      char sum[65]) {
    char key[32];
    snprintf(key, sizeof(key), "| `%s.csv` | ", name);
    const char *blk = strstr(md, "<!-- update-oui:begin -->");
    const char *p = blk ? strstr(blk, key) : NULL;
    if (!p) return -1;
    p = strchr(p + strlen(key), '|');           /* past the registry */
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

/* web/data/ is the four registry files SOURCE.md names, byte for byte:
 * a CSV refreshed or edited without `make update-oui` rewriting the
 * hashes fails here. Seen red with one hex digit of oui.csv's hash in
 * SOURCE.md changed. */
static void test_committed_registry_matches_source(void) {
    size_t len;
    char *md = slurp_file("web/data/SOURCE.md", &len);
    WT_ASSERT(md != NULL);
    if (!md) return;
    for (int i = 0; i < 4; i++) {
        long rows = -1;
        char want[65] = "";
        WT_EQ(source_row(md, REG_FILES[i], &rows, want), 0);
        char p[64];
        snprintf(p, sizeof(p), "web/data/%s.csv", REG_FILES[i]);
        size_t n = 0;
        char *csv = slurp_file(p, &n);
        WT_ASSERT(csv != NULL);
        if (!csv) continue;
        uint8_t d[32];
        web_sha256(csv, n, d);
        char got[65];
        for (int k = 0; k < 32; k++) snprintf(got + 2 * k, 3, "%02x", d[k]);
        WT_ASSERT(!strcmp(got, want));
        if (strcmp(got, want))
            fprintf(stderr, "  %s: sha256 %s, SOURCE.md says %s\n", p, got, want);
        WT_ASSERT(rows > 1000);
        free(csv);
    }
    free(md);
}

/* The builder on the whole committed registry, in bounded time. Until
 * 2026-10-26 each file had its own name index starting at 4096 slots
 * and rehashed every name so far into it: after oui.csv's ~40,000 names
 * the probe on mam.csv never ended. Seen red (the bound fired) with
 * that per-file index restored. The counts are SOURCE.md's rows: every
 * row is an entry or a later duplicate of one. */
static void test_committed_registry_builds_in_time(void) {
    bounded_t r;
    WT_EQ(run_bounded(build_committed, "web/data", 60, &r), 0);
    WT_EQ(r.rc, 0);
    size_t len;
    char *md = slurp_file("web/data/SOURCE.md", &len);
    WT_ASSERT(md != NULL);
    if (!md) return;
    long rows[4] = { 0, 0, 0, 0 };
    char sum[65];
    for (int i = 0; i < 4; i++)
        WT_EQ(source_row(md, REG_FILES[i], &rows[i], sum), 0);
    free(md);
    long dup = (long)r.duplicates;
    long mal = r.counts[WEB_OUI_MAL], mam = r.counts[WEB_OUI_MAM],
         mas = r.counts[WEB_OUI_MAS];
    WT_EQ(mal + mam + mas + dup, rows[0] + rows[1] + rows[2] + rows[3]);
    WT_ASSERT(mal <= rows[0] && mal + dup >= rows[0]);
    WT_ASSERT(mam <= rows[1] && mam + dup >= rows[1]);
    WT_ASSERT(mas <= rows[2] + rows[3] && mas + dup >= rows[2] + rows[3]);
    WT_EQ(r.skipped, 0);
    WT_ASSERT(r.nnames > 5000 && r.nnames <= r.n);
}

#define BIG_NAMES 6000

/* A first file of more distinct names than the old 4096-slot start, and
 * a second whose names are one the first already holds and one new. */
static void build_two_synthetic(const char *dir, bounded_t *r) {
    static oui_build_t b;
    oui_build_init(&b);
    char p1[128], p2[128];
    snprintf(p1, sizeof(p1), "%s/big.csv", dir);
    snprintf(p2, sizeof(p2), "%s/second.csv", dir);
    r->rc = oui_build_csv(&b, p1);
    if (r->rc == 0) r->rc = oui_build_csv(&b, p2);
    if (r->rc != 0) fprintf(stderr, "  %s\n", b.err);
    if (r->rc == 0) r->rc = oui_build_finish(&b, "ieee");
    fill(&b, r);
    r->probe = -1;
    uint8_t m[6] = { 0x70, 0xb3, 0xd5, 0x20, 0, 1 };   /* the MA-M row */
    web_oui_hit_t h;
    if (r->rc == 0 && web_oui_lookup(&b.tab, m, &h) == 1 &&
        !strcmp(h.name, "Vendor 00042"))
        r->probe = 42;
    oui_build_free(&b);
}

/* The hang's shape without the real registry: more than 5,000 names,
 * then a second file. Seen red (the bound fired) with the per-file
 * index restored. */
static void test_second_file_after_many_names(void) {
    char p[128];
    path_in(p, sizeof(p), "big.csv");
    FILE *f = fopen(p, "wb");
    WT_ASSERT(f != NULL);
    if (!f) return;
    fputs("Registry,Assignment,Organization Name,Organization Address\n", f);
    for (unsigned i = 0; i < BIG_NAMES; i++)
        fprintf(f, "MA-L,%06X,Vendor %05u,x\n", 0x100000u + i, i);
    fclose(f);
    write_file("second.csv",
               "Registry,Assignment,Organization Name,Organization Address\n"
               "MA-M,70B3D52,Vendor 00042,x\n"
               "MA-S,70B3D5F2A,A New One,x\n");
    bounded_t r;
    WT_EQ(run_bounded(build_two_synthetic, g_dir, 20, &r), 0);
    WT_EQ(r.rc, 0);
    WT_EQ(r.counts[WEB_OUI_MAL], BIG_NAMES);
    WT_EQ(r.counts[WEB_OUI_MAM], 1);
    WT_EQ(r.counts[WEB_OUI_MAS], 1);
    WT_EQ(r.nnames, BIG_NAMES + 1);      /* "Vendor 00042" is the first's */
    WT_EQ(r.probe, 42);
    unlink(p);
    path_in(p, sizeof(p), "second.csv");
    unlink(p);
}

/* needle's occurrences on lines that are not # comments. */
static int code_mentions(const char *text, const char *needle) {
    int n = 0;
    for (const char *q = text; (q = strstr(q, needle)) != NULL; q++) {
        const char *bol = q;
        while (bol > text && bol[-1] != '\n') bol--;
        while (*bol == ' ' || *bol == '\t') bol++;
        if (*bol != '#') n++;
    }
    return n;
}

/* `make update-oui` is by hand only: outside comments the Makefile
 * names the script once (the rule's recipe) and the target twice (.PHONY
 * and the rule), and CI never mentions either, so no build, test or CI
 * job reaches the network for the registry. Seen red with update-oui
 * added to web's prerequisites, and with a CI step running it. */
static void test_update_oui_is_never_automatic(void) {
    size_t len;
    char *mk = slurp_file("Makefile", &len);
    WT_ASSERT(mk != NULL);
    if (!mk) return;
    WT_EQ(code_mentions(mk, "update_oui"), 1);
    WT_EQ(code_mentions(mk, "update-oui"), 2);
    WT_ASSERT(strstr(mk, "\nupdate-oui:\n") != NULL);
    free(mk);
    char *ci = slurp_file(".github/workflows/ci.yml", &len);
    WT_ASSERT(ci != NULL);
    if (!ci) return;
    WT_LACKS(ci, "update-oui");
    WT_LACKS(ci, "update_oui");
    free(ci);
}

void run_oui_tests(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/slothweb-oui-XXXXXX");
    if (!mkdtemp(g_dir)) { WT_ASSERT(!"mkdtemp"); return; }
    write_file("oui.csv", OUI_CSV);
    write_file("mam.csv", MAM_CSV);
    write_file("oui36.csv", MAS_CSV);
    WT_RUN(test_lookup_by_block);
    WT_RUN(test_misses_and_bits);
    WT_RUN(test_emit);
    WT_RUN(test_bad_csv_fails);
    WT_RUN(test_names_cleaned);
    WT_RUN(test_sloth_fallback);
    WT_RUN(test_builtin_table);
    WT_RUN(test_committed_registry_matches_source);
    WT_RUN(test_committed_registry_builds_in_time);
    WT_RUN(test_second_file_after_many_names);
    WT_RUN(test_update_oui_is_never_automatic);
    oui_build_free(&B);
    char p[128];
    path_in(p, sizeof(p), "oui.csv");   unlink(p);
    path_in(p, sizeof(p), "mam.csv");   unlink(p);
    path_in(p, sizeof(p), "oui36.csv"); unlink(p);
    rmdir(g_dir);
}
