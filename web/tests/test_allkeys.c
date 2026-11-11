/* The Activity graph's "keys: all" (2026-11-11): /api/series/all
 * (web_allkeys.h), every key of one metric (the rollup's and the
 * store's, not /api/keys' 256) in at most cols cells, a page of keys to
 * an answer; and the page's half, web/ui/allkeys.js.
 *
 * allkeys.js is two halves, as glyph.js is. The pure half (the legend's
 * order, the "N of M keys" words, the tier a window is read in, the
 * multi-key mark list, its frame, the presence strips) is ported here
 * line for line, and the JS it ports is pinned verbatim out of the
 * served page, so a change on either side fails `make web-test`
 * (test_glyph.c's mechanism; no node). The other half is pinned by
 * whole functions (agents/AGENTS.md).
 *
 * Absence assertions, each seen red under the named mutation and
 * restored (2026-11-11, and again after the cap was lifted).
 * The route, web_allkeys.c and web_store_keys_after():
 *   - no key answered twice across pages: the after-skip's `<= 0` made
 *     `< 0` (a page's last key came back as the next one's first; the
 *     walks counted the repeats);
 *   - no more than WEB_ALLKEYS_PAGE keys an answer: the `done ==
 *     WEB_ALLKEYS_PAGE` stop removed (150 came back);
 *   - a key outside the scope is not answered: key_in() returning 1
 *     (eth0 under Monitor, wlan0mon under Local); a metric outside it
 *     answers no key: key_in() and metric_in() both returning 1 (either
 *     alone is covered by the other for a metric that is not by key);
 *   - no out_of_scope on a metric the scope holds: the `!in` test made 1;
 *   - an empty cell is not in "p": the `cell[x].t < 0 || !cell[x].n`
 *     skip removed (a 0 for each);
 *   - a store key with no bucket in the window is not answered: the
 *     EXISTS probe's bound on t removed (10.0.5.9, a day old);
 *   - another metric's key is not answered: the statement's `x.metric =
 *     ?1` made `?1 = ?1` (10.0.5.4);
 *   - no total_min on a count that is whole: the `store_more` test
 *     dropped from it.
 * The port of allkeys.js below:
 *   - no band without a picked row: the `opt->pick >= 0` test replaced
 *     by row 0 (a band with no key picked);
 *   - no line across a gap: `left` made `j > 0`;
 *   - no line through fewer than five points: `dots` forced 0;
 *   - no label past the first LABELS rows: the `lc >= opt->labels` skip
 *     removed (eight labels);
 *   - no label without room for one: the `opt->padR > 8` test removed;
 *   - no colour on an unfocused row: the dim test dropped from lines()
 *     and, separately, from strips();
 *   - no grey row without a focus: the dim test's `focus >= 0` dropped;
 *   - the dim token is never --rule: AK_DIM made "--rule";
 *   - no token but a key's colour and grey in the lines: the last mark
 *     given "--heat-3";
 *   - no range while every row is a line: the fold's loop started at
 *     row 0; no line, dot or last for a folded row: the line loop's
 *     bound made every row;
 *   - no now mark outside the window: frame()'s bound on now dropped;
 *   - nothing in the frame --signal but the now mark: an axis given it.
 * The page, allkeys.js:
 *   - no innerHTML, insertAdjacentHTML, document.write, setAttribute,
 *     eval(, createLinearGradient, shadowBlur or createPattern: a comment
 *     line holding all eight added to the module (eight red);
 *   - one "--signal" in the module: a second put on the focus row.
 * Not isolated, and so not claimed: that a refused `after` is never
 * echoed (the route has no path that writes a parameter's value); and
 * the route's `bound` (a page stops at the last store key it read when
 * the store has more): the merge takes at most a page from a page and
 * one of the store's keys, so the bound only binds when the scope has
 * dropped some of them, which needs more by-key store keys than a
 * metric scoped by key has. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../../src/ip_color.h"
#include "web_allkeys.h"
#include "web_assets.h"
#include "web_live.h"
#include "web_metrics.h"
#include "web_rollup.h"
#include "web_routes.h"
#include "web_series.h"
#include "web_slothdb.h"
#include "web_store.h"
#include "web_tsdb.h"
#include "wtest.h"
#include "wt_tmp.h"

#define T 1792627200LL                  /* a whole hour, unix seconds */

static const char *page(void) { return (const char *)web_page; }

/* ── the route ──────────────────────────────────────────────────── */

static web_rollup_t ru;
static web_tsdb_t   ts;
static web_live_t   g_live;
static char         body[65536];
static char         g_out[65536 + 2048];

static void mem_tsdb(int max_keys) {
    char err[64];
    WT_EQ(web_rollup_init(&ru, max_keys, 0, err, sizeof(err)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, NULL, 30, 256, NULL, NULL), 0);
}
static void mem_done(void) {
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
}

static int parse(const char *q, int store_on, web_allkeys_q_t *out, char *why) {
    return web_allkeys_parse(q, T + 5, store_on, out, why, 48);
}
static void bad(const char *q, int store_on, const char *want) {
    web_allkeys_q_t s;
    char why[48] = "";
    WT_EQ(parse(q, store_on, &s, why), -1);
    if (strcmp(why, want)) fprintf(stderr, "  query \"%s\": got %s, want %s\n", q, why, want);
    WT_ASSERT(!strcmp(why, want));
}

/* The answer for a query string, NUL-terminated in body; its length. */
static size_t answer(const char *qs, int store_on) {
    web_allkeys_q_t q;
    char why[48] = "";
    int rc = web_allkeys_parse(qs, T + 86400, store_on, &q, why, sizeof(why));
    WT_EQ(rc, 0);
    if (rc != 0) { body[0] = '\0'; return 0; }
    size_t n = web_allkeys_json(&ts, &q, body, sizeof(body) - 1);
    body[n] = '\0';
    return n;
}

/* The keys of an answer, in its order, into out; how many. */
static int keys_of(const char *b, char out[][WEB_KEY_MAX + 1], int max) {
    int n = 0;
    for (const char *p = strstr(b, "{\"key\":\""); p && n < max; p = strstr(p + 1, "{\"key\":\"")) {
        const char *v = p + 8, *e = strchr(v, '"');
        if (!e || (size_t)(e - v) > WEB_KEY_MAX) break;
        memcpy(out[n], v, (size_t)(e - v));
        out[n][e - v] = '\0';
        n++;
    }
    return n;
}

static void test_parameters(void) {
    web_allkeys_q_t q;
    char why[48];
    WT_EQ(parse("metric=host.rx_rate", 0, &q, why), 0);
    WT_EQ(q.metric, WM_HOST_RX);
    WT_EQ(q.tier, WEB_TIER_FINE);
    WT_EQ(q.cols, WEB_ALLKEYS_COLS_DEF);
    WT_EQ(q.to, T + 10);
    WT_EQ(q.from, T + 10 - 3600);
    WT_EQ(q.has_after, 0);
    WT_EQ(parse("metric=dev.frames&cols=480&after=AA%3ABB%3Acc%3Add%3Aee%3AFF&from=100&to=200",
                0, &q, why), 0);
    WT_EQ(q.cols, 480);
    WT_EQ(q.has_after, 1);
    WT_ASSERT(!strcmp(q.after, "aa:bb:cc:dd:ee:ff"));
    /* The longest window each tier is offered: 24 h of 10 s, 7 d of
     * minutes, 400 d of hours. */
    WT_EQ(parse("metric=host.rx_rate&from=1000&to=87400", 0, &q, why), 0);
    WT_EQ(parse("metric=host.rx_rate&tier=minute&from=1000&to=605800", 1, &q, why), 0);
    WT_EQ(parse("metric=host.rx_rate&tier=hour&from=1000&to=34561000", 1, &q, why), 0);

    bad("", 0, "missing_metric");
    bad("metric=nope", 0, "unknown_metric");
    bad("metric=host.rx_rate&key=10.0.0.1", 0, "unknown_parameter");
    bad("metric=host.rx_rate&cols=7", 0, "bad_cols");
    bad("metric=host.rx_rate&cols=481", 0, "bad_cols");
    bad("metric=host.rx_rate&cols=x", 0, "bad_cols");
    bad("metric=host.rx_rate&cols=240&cols=240", 0, "repeated_parameter");
    bad("metric=host.rx_rate&after=10.0.0.256", 0, "bad_after");
    bad("metric=host.rx_rate&after=%3Cscript%3E", 0, "bad_after");
    bad("metric=conns.total&after=x", 0, "bad_after");
    bad("metric=host.rx_rate&tier=minute", 0, "tier_unavailable");
    bad("metric=host.rx_rate&tier=week", 1, "unknown_tier");
    bad("metric=host.rx_rate&from=200&to=100", 0, "empty_range");
    bad("metric=host.rx_rate&from=x&to=100", 0, "bad_from");
    bad("metric=host.rx_rate&from=1000&to=101810", 0, "range_too_long");
    bad("metric=host.rx_rate&tier=minute&from=1000&to=605860", 1, "range_too_long");
    bad("metric=host.rx_rate&from=1792627000&to=1792713606", 0, "to_in_future");
}

/* The parameters under a few thousand generated query strings, from a
 * fixed seed: the route's names and others, values of every kind the
 * decoder meets (empty, the longest a number may be and one digit
 * more, escapes whole, cut and not hex, a byte over 0x7f, a value past
 * WEB_PARAM_MAX), '=' and '&' left out and doubled. The string is in a
 * block of exactly its length. A query that is taken is one the answer
 * can be built from without another check (the range not empty and no
 * longer than the buckets an answer reads, the cells no more than
 * cols); one that is not says why in a word of the route's own. What
 * it found on 2026-11-11: nothing. */
static void test_parameters_generated(void) {
    static const char *const NAMES[] = { "metric", "tier", "from", "to", "cols", "after",
                                         "key", "Metric", "", "scope" };
    static const char *const VALS[] = {
        "host.rx_rate", "dev.frames", "conns.total", "alerts.fired", "nope",
        "fine", "minute", "hour", "0", "8", "240", "480", "481", "1000", "87400",
        "99999999999", "100000000000", "-1", "1e3", "+5", "", "%", "%3", "%zz", "%00", "%3C",
        "aa%3Abb%3Acc%3Add%3Aee%3Aff", "10.0.0.1", "\x80\xff", "a b",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    };
    uint32_t x = 0xa11ce75;
    int taken = 0;
#define NEXT() (x = x * 1664525u + 1013904223u, x >> 8)
    for (int it = 0; it < 6000; it++) {
        char qs[1024];
        size_t o = 0;
        /* Most begin as a query the route takes, so both sides are reached. */
        if (NEXT() % 3) o += (size_t)snprintf(qs, sizeof(qs), "metric=%s",
                                              VALS[NEXT() % 4]);
        for (int k = 0, n = (int)(NEXT() % 5); k < n; k++) {
            const char *nm = NAMES[NEXT() % (sizeof(NAMES) / sizeof(NAMES[0]))];
            const char *v = VALS[NEXT() % (sizeof(VALS) / sizeof(VALS[0]))];
            unsigned shape = NEXT() % 16;
            o += (size_t)snprintf(qs + o, sizeof(qs) - o, "%s%s%s%s",
                                  o && shape != 0 ? "&" : "", shape == 1 ? "&" : "", nm,
                                  shape == 2 ? "" : shape == 3 ? "==" : "=");
            o += (size_t)snprintf(qs + o, sizeof(qs) - o, "%s", v);
        }
        qs[o] = '\0';
        char *q = malloc(o + 1);
        WT_ASSERT(q != NULL);
        if (!q) return;
        memcpy(q, qs, o + 1);
        int store_on = (int)(NEXT() % 2);
        web_allkeys_q_t s;
        char why[48] = "";
        int rc = web_allkeys_parse(q, T + 5, store_on, &s, why, sizeof(why));
        WT_ASSERT(rc == 0 || rc == -1);
        if (rc == 0) {
            taken++;
            long long step = web_tier_step(s.tier), cs = 0;
            int nc = 0;
            WT_ASSERT(s.metric >= 0 && s.metric < WM_COUNT);
            WT_ASSERT(s.tier >= 0 && s.tier < WEB_TIER_COUNT);
            WT_ASSERT(s.tier == WEB_TIER_FINE || store_on);
            WT_ASSERT(s.from >= 0 && s.from < s.to && s.to <= T + 5 + 86400);
            WT_ASSERT(s.to - s.from <= (long long)WEB_ALLKEYS_BUCKETS * step);
            WT_ASSERT(s.cols >= WEB_ALLKEYS_COLS_MIN && s.cols <= WEB_ALLKEYS_COLS_MAX);
            WT_ASSERT(s.has_after == 0 || s.has_after == 1);
            WT_ASSERT(memchr(s.after, '\0', sizeof(s.after)) != NULL);
            WT_ASSERT(s.has_after || !s.after[0]);
            web_allkeys_cells(s.tier, s.from, s.to, s.cols, &cs, &nc);
            WT_ASSERT(nc >= 1 && nc <= s.cols && cs >= step && cs % step == 0);
            WT_ASSERT(cs * nc >= s.to - s.from);
        } else {
            WT_ASSERT(why[0] != '\0' && strspn(why, "abcdefghijklmnopqrstuvwxyz_") == strlen(why));
        }
        free(q);
    }
#undef NEXT
    WT_ASSERT(taken > 300);            /* the generator does reach the accepting side */
}

/* A cell is a whole number of buckets, the least that fits cols. */
static void test_cells(void) {
    long long cs;
    int nc;
    web_allkeys_cells(WEB_TIER_FINE, 0, 3600, 480, &cs, &nc);
    WT_EQ(cs, 10); WT_EQ(nc, 360);
    web_allkeys_cells(WEB_TIER_FINE, 0, 3600, 240, &cs, &nc);
    WT_EQ(cs, 20); WT_EQ(nc, 180);
    web_allkeys_cells(WEB_TIER_FINE, 0, 86400, 480, &cs, &nc);
    WT_EQ(cs, 180); WT_EQ(nc, 480);
    web_allkeys_cells(WEB_TIER_FINE, 0, 86400, 479, &cs, &nc);
    WT_EQ(cs, 190); WT_EQ(nc, 455);
    web_allkeys_cells(WEB_TIER_MINUTE, 0, 604800, 480, &cs, &nc);
    WT_EQ(cs, 1260); WT_EQ(nc, 480);
    web_allkeys_cells(WEB_TIER_HOUR, 0, 2592000, 480, &cs, &nc);
    WT_EQ(cs, 7200); WT_EQ(nc, 360);
    web_allkeys_cells(WEB_TIER_HOUR, 0, 34560000, 8, &cs, &nc);
    WT_EQ(cs, 4320000); WT_EQ(nc, 8);
}

/* The shape: keys in byte order, "p" sparse and flat, a gauge's cell
 * its buckets' mean, a counter's its sum, presence's its max. */
static void test_answer_shape(void) {
    mem_tsdb(64);
    /* 10.0.0.2: buckets 0..3 at 2, 4, 6, 8; cols 8 over 80 s is 10 s
     * cells, cols 8 over 160 s is 20 s cells of two buckets each. */
    for (int b = 0; b < 4; b++)
        web_rollup_add(&ru, WM_HOST_RX, "10.0.0.2", 2.0 * (b + 1), T + b * 10);
    web_rollup_add(&ru, WM_HOST_RX, "10.0.0.2", 0, T + 70);     /* closes them */
    web_rollup_add(&ru, WM_HOST_RX, "10.0.0.10", 5, T + 70);
    web_rollup_add(&ru, WM_HOST_RX, "10.0.0.1", 7, T + 150);
    char qs[160];
    snprintf(qs, sizeof(qs), "metric=host.rx_rate&cols=8&from=%lld&to=%lld", T, T + 160);
    size_t n = answer(qs, 0);
    WT_ASSERT(n > 0);
    WT_HAS(body, "{\"metric\":\"host.rx_rate\",\"tier\":\"fine\",\"step\":10,\"cell\":20,\"cells\":8,"
                 "\"kind\":\"gauge\",\"unit\":\"B/s\",\"keykind\":\"ip\",");
    WT_HAS(body, "\"total\":3,\"keys\":[");
    /* Byte order: "10.0.0.1" < "10.0.0.10" < "10.0.0.2". */
    WT_HAS(body, "\"keys\":[{\"key\":\"10.0.0.1\",\"p\":[7,7]},"
                 "{\"key\":\"10.0.0.10\",\"p\":[3,5]},"
                 "{\"key\":\"10.0.0.2\",\"p\":[0,3,1,7,3,0]}]");
    WT_HAS(body, "],\"more\":false,\"next\":null,\"source\":\"memory\"}\n");
    /* An empty cell is absent, never a 0: cell 2 of 10.0.0.2. */
    WT_LACKS(body, "[0,3,1,7,2,");
    /* A counter's cell is the sum of its buckets. */
    for (int b = 0; b < 4; b++)
        web_rollup_add(&ru, WM_DNS_QUERIES, "10.0.0.2", 1, T + b * 10);
    web_rollup_add(&ru, WM_DNS_QUERIES, "10.0.0.2", 1, T + 35);
    snprintf(qs, sizeof(qs), "metric=dns.queries&cols=8&from=%lld&to=%lld", T, T + 160);
    WT_ASSERT(answer(qs, 0) > 0);
    WT_HAS(body, "\"kind\":\"counter\"");
    WT_HAS(body, "{\"key\":\"10.0.0.2\",\"p\":[0,2,1,3]}");
    /* Presence: 1 where any bucket of the cell was present. */
    web_rollup_add(&ru, WM_DEV_PRESENT, "02:00:00:00:00:01", 1, T + 40);
    snprintf(qs, sizeof(qs), "metric=dev.present&cols=8&from=%lld&to=%lld", T, T + 160);
    WT_ASSERT(answer(qs, 0) > 0);
    WT_HAS(body, "\"kind\":\"presence\"");
    WT_HAS(body, "{\"key\":\"02:00:00:00:00:01\",\"p\":[2,1]}");
    /* A global metric is one key, "". */
    web_rollup_add(&ru, WM_CONNS_TOTAL, "", 12, T + 40);
    snprintf(qs, sizeof(qs), "metric=conns.total&cols=8&from=%lld&to=%lld", T, T + 160);
    WT_ASSERT(answer(qs, 0) > 0);
    WT_HAS(body, "\"keykind\":\"\",");
    WT_HAS(body, "\"total\":1,\"keys\":[{\"key\":\"\",\"p\":[2,12]}]");
    /* No key at all: an empty list, not an error. */
    snprintf(qs, sizeof(qs), "metric=flow.rdp&cols=8&from=%lld&to=%lld", T, T + 160);
    WT_ASSERT(answer(qs, 0) > 0);
    WT_HAS(body, "\"total\":0,\"keys\":[],\"more\":false,\"next\":null,");
    mem_done();
}

/* Paging by key: WEB_ALLKEYS_PAGE keys an answer, the next asked for
 * with after=next, no key twice and none missed; "total" on the first
 * answer only. */
static void test_paging(void) {
    mem_tsdb(512);
    char k[32], qs[200];
    for (int i = 0; i < 150; i++) {
        snprintf(k, sizeof(k), "10.0.1.%d", i + 1);
        web_rollup_add(&ru, WM_HOST_RX, k, i + 1, T + 10);
    }
    snprintf(qs, sizeof(qs), "metric=host.rx_rate&cols=8&from=%lld&to=%lld", T, T + 80);
    WT_ASSERT(answer(qs, 0) > 0);
    static char a[160][WEB_KEY_MAX + 1], b[160][WEB_KEY_MAX + 1];
    int na = keys_of(body, a, 160);
    WT_EQ(na, WEB_ALLKEYS_PAGE);
    WT_HAS(body, "\"total\":150,\"keys\":[");
    char want[96];
    snprintf(want, sizeof(want), "],\"more\":true,\"next\":\"%s\",", a[na - 1]);
    WT_HAS(body, want);
    for (int i = 1; i < na; i++) WT_ASSERT(strcmp(a[i - 1], a[i]) < 0);
    snprintf(qs, sizeof(qs), "metric=host.rx_rate&cols=8&from=%lld&to=%lld&after=%s", T, T + 80,
             a[na - 1]);
    WT_ASSERT(answer(qs, 0) > 0);
    int nb = keys_of(body, b, 160);
    WT_EQ(nb, 150 - WEB_ALLKEYS_PAGE);
    WT_HAS(body, "\"total\":null,\"keys\":[");
    WT_HAS(body, "],\"more\":false,\"next\":null,");
    /* None twice: the second page starts after the first's last. */
    for (int i = 0; i < nb; i++) WT_ASSERT(strcmp(b[i], a[na - 1]) > 0);
    mem_done();
}

static double ms_since(const struct timespec *a) {
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    return (double)(b.tv_sec - a->tv_sec) * 1e3 + (double)(b.tv_nsec - a->tv_nsec) / 1e6;
}

/* Walk every page of a query; the keys seen, the answers, the slowest
 * answer and the whole walk in ms. The keys must come in byte order,
 * none twice: counted in *dups. */
typedef struct { int keys, pages, dups; long long total; double worst_ms, all_ms; size_t bytes; } walk_t;
static walk_t walk(const char *base, int store_on) {
    static char got[160][WEB_KEY_MAX + 1];
    char qs[320], after[WEB_KEY_MAX + 1] = "", prev[WEB_KEY_MAX + 1] = "";
    walk_t w;
    memset(&w, 0, sizeof(w));
    w.total = -1;
    for (;;) {
        if (w.pages) snprintf(qs, sizeof(qs), "%s&after=%s", base, after);
        else snprintf(qs, sizeof(qs), "%s", base);
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        size_t n = answer(qs, store_on);
        double ms = ms_since(&t0);
        if (!n) break;
        w.bytes += n;
        w.all_ms += ms;
        if (ms > w.worst_ms) w.worst_ms = ms;
        const char *tp = strstr(body, "\"total\":");
        if (!w.pages && tp) w.total = atoll(tp + 8);
        int k = keys_of(body, got, 160);
        w.pages++;
        for (int i = 0; i < k; i++) {
            if (w.keys + i > 0 && strcmp(got[i], prev) <= 0) w.dups++;
            snprintf(prev, sizeof(prev), "%s", got[i]);
        }
        w.keys += k;
        if (!strstr(body, "\"more\":true") || !k || w.pages > 20000) break;
        snprintf(after, sizeof(after), "%s", got[k - 1]);
    }
    return w;
}

/* "Lift the cap" (owner ruling 2026-11-11): every key is answered, not
 * /api/keys' 256 most recently seen. 300 devices, each seen later than
 * the one before it, and the 44 oldest are among them. */
static void test_every_key_is_walked(void) {
    mem_tsdb(1024);
    char k[32], qs[200];
    for (int i = 0; i < 300; i++) {
        snprintf(k, sizeof(k), "02:00:00:00:%02x:%02x", i / 256, i % 256);
        web_rollup_add(&ru, WM_DEV_FRAMES, k, 1, T + i);
    }
    snprintf(qs, sizeof(qs), "metric=dev.frames&cols=8&from=%lld&to=%lld", T, T + 3600);
    walk_t w = walk(qs, 0);
    WT_EQ(w.keys, 300);
    WT_EQ(w.total, 300);
    WT_EQ(w.pages, 3);
    WT_EQ(w.dups, 0);
    WT_ASSERT(WEB_KEYS_MAX < 300);       /* /api/keys would have listed fewer */
    WT_ASSERT(answer(qs, 0) > 0);
    WT_HAS(body, "{\"key\":\"02:00:00:00:00:00\",");      /* the oldest seen */
    /* An answer takes keys for web_allkeys_budget_ms and then stops: at
     * 0 it holds the one key it always answers, and the walk is still
     * every key once. */
    web_allkeys_budget_ms = 0;
    WT_ASSERT(answer(qs, 0) > 0);
    static char one[8][WEB_KEY_MAX + 1];
    WT_EQ(keys_of(body, one, 8), 1);
    WT_HAS(body, "],\"more\":true,\"next\":\"02:00:00:00:00:00\",");
    w = walk(qs, 0);
    web_allkeys_budget_ms = WEB_ALLKEYS_ANSWER_MS;
    WT_EQ(w.keys, 300);
    WT_EQ(w.pages, 300);
    WT_EQ(w.dups, 0);
    mem_done();
}

/* The cost of the most keys a rollup can hold: --web-max-keys' maximum,
 * 8,192 devices, 16 closed buckets each (the ring's 131,072 rows), every
 * key walked. Each answer against the request budget; the measured
 * times are printed. */
static void test_walk_of_8192_keys_from_memory(void) {
    mem_tsdb(WEB_MAX_KEYS_MAX);
    char k[32], qs[200];
    for (int b = 0; b <= 16; b++)
        for (int i = 0; i < WEB_MAX_KEYS_MAX; i++) {
            snprintf(k, sizeof(k), "02:00:00:00:%02x:%02x", i / 256, i % 256);
            web_rollup_add(&ru, WM_DEV_FRAMES, k, 1 + (b + i) % 7, T + (long long)b * 10);
        }
    snprintf(qs, sizeof(qs), "metric=dev.frames&cols=64&from=%lld&to=%lld", T, T + 3600);
    walk_t w = walk(qs, 0);
    fprintf(stderr, "  /api/series/all, memory: %d keys walked in %d answers, %zu bytes, "
            "%.0f ms in all, the slowest answer %.1f ms (budget %d ms)\n", w.keys, w.pages,
            w.bytes, w.all_ms, w.worst_ms, WEB_SDB_HTTP_MS * web_sdb_test_budget_scale);
    WT_EQ(w.keys, WEB_MAX_KEYS_MAX);
    WT_EQ(w.total, WEB_MAX_KEYS_MAX);
    WT_EQ(w.dups, 0);
    WT_ASSERT(w.worst_ms < (double)WEB_SDB_HTTP_MS * web_sdb_test_budget_scale);
    mem_done();
}

/* An answer that is full stops before WEB_ALLKEYS_PAGE keys, whole: the
 * key that did not fit is the next answer's first. 40 keys with every
 * one of 480 cells filled with a value of eight bytes. */
static void test_a_full_answer_pages(void) {
    mem_tsdb(256);
    char k[32], qs[200];
    for (int b = 0; b < 480; b++)
        for (int i = 0; i < 40; i++) {
            snprintf(k, sizeof(k), "10.0.2.%d", i + 1);
            web_rollup_add(&ru, WM_HOST_RX, k, -5000.5 - b - i * 0.01, T + b * 10);
        }
    snprintf(qs, sizeof(qs), "metric=host.rx_rate&cols=480&from=%lld&to=%lld", T, T + 4800);
    size_t n = answer(qs, 0);
    WT_ASSERT(n > 0 && n <= sizeof(body) - 1);
    static char a[64][WEB_KEY_MAX + 1];
    int na = keys_of(body, a, 64);
    WT_ASSERT(na >= 7 && na < WEB_ALLKEYS_PAGE);
    WT_HAS(body, "\"more\":true,\"next\":\"");
    WT_ASSERT(n >= 2 && !strcmp(body + n - 2, "}\n"));
    /* Every key answered is whole: 480 cells each. */
    int cells = 0;
    for (const char *p = body; (p = strstr(p, ",-5")) != NULL; p++) cells++;
    WT_EQ(cells, na * 480);
    /* A buffer one key does not fit in is no answer, not a cut one. */
    web_allkeys_q_t q;
    char why[48];
    WT_EQ(web_allkeys_parse(qs, T + 86400, 0, &q, why, sizeof(why)), 0);
    WT_EQ(web_allkeys_json(&ts, &q, body, 2048), 0);
    mem_done();
}

static int route(const web_health_t *h, const char *path, const char *query) {
    web_req_t *rq = calloc(1, sizeof(*rq));
    web_resp_t r;
    if (!rq) return -1;
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query);
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    int rc = web_route(rq, h, 1, g_out, sizeof(g_out) - 1, &r);
    free(rq);
    if (rc != 0) return -1;
    g_out[r.out_len] = '\0';
    return r.status;
}

/* Through the router, and under a scope: the keys are the scope's, as
 * /api/keys lists them. */
static void test_route_and_scope(void) {
    mem_tsdb(64);
    web_live_init(&g_live, "unix:/test/sloth.sock");
    web_rollup_add(&ru, WM_DNS_QUERIES, "10.0.2.20", 1, T);
    web_rollup_add(&ru, WM_WIFI_DEAUTH, "02:00:00:00:00:a1", 1, T);
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.live = &g_live;
    h.tsdb = &ts;
    h.wall_s = T + 5;
    WT_EQ(route(&h, "/api/series/all", "metric=dns.queries&cols=8"), 200);
    WT_HAS(g_out, "Content-Type: application/json\r\n");
    WT_HAS(g_out, "Cache-Control: no-store\r\n");
    WT_HAS(g_out, "{\"metric\":\"dns.queries\",");
    WT_HAS(g_out, "{\"key\":\"10.0.2.20\",\"p\":[");
    WT_EQ(route(&h, "/api/series/all", "metric=dns.queries&cols=8&scope=local"), 200);
    WT_HAS(g_out, "{\"scope\":\"local\",\"metric\":\"dns.queries\",");
    WT_HAS(g_out, "{\"key\":\"10.0.2.20\",\"p\":[");
    WT_LACKS(g_out, "out_of_scope");
    /* Monitor holds no dns.queries; Local no wifi.deauth. */
    WT_EQ(route(&h, "/api/series/all", "metric=dns.queries&cols=8&scope=monitor"), 200);
    WT_HAS(g_out, "\"total\":0,\"out_of_scope\":true,\"keys\":[],");
    WT_LACKS(g_out, "10.0.2.20");
    WT_EQ(route(&h, "/api/series/all", "metric=wifi.deauth&cols=8&scope=local"), 200);
    WT_HAS(g_out, "\"out_of_scope\":true,\"keys\":[],");
    WT_LACKS(g_out, "02:00:00:00:00:a1");
    WT_EQ(route(&h, "/api/series/all", "metric=wifi.deauth&cols=8&scope=monitor"), 200);
    WT_HAS(g_out, "{\"key\":\"02:00:00:00:00:a1\",\"p\":[");
    /* A bad parameter is a 400 in a word of our own, never the value. */
    WT_EQ(route(&h, "/api/series/all", "metric=dns.queries&cols=9999"), 400);
    WT_HAS(g_out, "{\"error\":\"bad_cols\"}");
    WT_EQ(route(&h, "/api/series/all", "metric=dns.queries&after=%3Cscript%3E"), 400);
    WT_HAS(g_out, "{\"error\":\"bad_after\"}\n");
    WT_EQ(route(&h, "/api/series/all", "metric=dns.queries&tier=minute"), 400);
    WT_HAS(g_out, "tier_unavailable");
    h.tsdb = NULL;
    WT_EQ(route(&h, "/api/series/all", "metric=dns.queries"), 503);
    WT_HAS(g_out, "no_time_series");
    /* A metric scoped by its key: an interface by its radio. */
    web_rollup_add(&ru, WM_IFACE_RX, "eth0", 10, T);
    web_rollup_add(&ru, WM_IFACE_RX, "wlan0mon", 20, T);
    web_scope_ctx_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.given = 1;
    sc.nmon = 1;
    snprintf(sc.mon[0], sizeof(sc.mon[0]), "wlan0mon");
    web_allkeys_q_t q;
    char why[48], qs[160];
    snprintf(qs, sizeof(qs), "metric=iface.rx_rate&cols=8&from=%lld&to=%lld", T, T + 80);
    WT_EQ(web_allkeys_parse(qs, T + 5, 0, &q, why, sizeof(why)), 0);
    q.sc = &sc;
    sc.scope = WEB_SCOPE_MONITOR;
    size_t n = web_allkeys_json(&ts, &q, body, sizeof(body) - 1);
    body[n] = '\0';
    WT_HAS(body, "\"total\":1,\"keys\":[{\"key\":\"wlan0mon\",");
    WT_LACKS(body, "eth0");
    WT_LACKS(body, "out_of_scope");
    sc.scope = WEB_SCOPE_LOCAL;
    n = web_allkeys_json(&ts, &q, body, sizeof(body) - 1);
    body[n] = '\0';
    WT_HAS(body, "\"total\":1,\"keys\":[{\"key\":\"eth0\",");
    WT_LACKS(body, "wlan0mon");
    sc.scope = WEB_SCOPE_HYBRID;
    n = web_allkeys_json(&ts, &q, body, sizeof(body) - 1);
    body[n] = '\0';
    WT_HAS(body, "\"total\":2,\"keys\":[{\"key\":\"eth0\",");
    WT_HAS(body, "{\"key\":\"wlan0mon\",");
    mem_done();
}

/* The cost of the worst page memory can hold: 32 keys of 4,095 closed
 * buckets each fill the ring (131,072 rows), and one answer reads them
 * all into 480 cells a key. Timed against the request budget
 * (WEB_SDB_HTTP_MS, 250 ms), scaled under the sanitizers as every
 * timed read here is. The measured time is printed. */
static void test_worst_page_from_memory(void) {
    mem_tsdb(256);
    char k[32], qs[200];
    const int NB = 4095;
    for (int b = 0; b <= NB; b++)
        for (int i = 0; i < 32; i++) {
            snprintf(k, sizeof(k), "10.0.3.%d", i + 1);
            web_rollup_add(&ru, WM_HOST_RX, k, 1 + (b + i) % 97, T + (long long)b * 10);
        }
    snprintf(qs, sizeof(qs), "metric=host.rx_rate&cols=480&from=%lld&to=%lld", T,
             T + (long long)(NB + 1) * 10);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    size_t n = answer(qs, 0);
    double ms = ms_since(&t0);
    WT_ASSERT(n > 0);
    static char a[64][WEB_KEY_MAX + 1];
    int na = keys_of(body, a, 64);
    fprintf(stderr, "  /api/series/all, memory: %d keys of %d buckets in 480 cells, "
            "%zu bytes, %.1f ms (budget %d ms)\n", na, NB + 1, n, ms,
            WEB_SDB_HTTP_MS * web_sdb_test_budget_scale);
    WT_ASSERT(na >= 7);
    WT_ASSERT(ms < (double)WEB_SDB_HTTP_MS * web_sdb_test_budget_scale);
    mem_done();
}

#ifdef WITH_SQLITE
/* And the worst page the store can hold: 32 keys of 24 h at 10 s, 8,640
 * rows a key, 276,480 rows read for one answer. */
static void test_worst_page_from_the_store(void) {
    char dir[TEST_TMP_MAX];
    test_tmp_path(dir, sizeof(dir), "slothweb-allkeys-XXXXXX");
    WT_ASSERT(mkdtemp(dir) != NULL);
    char p[128], err[512], e2[64], qs[200];
    snprintf(p, sizeof(p), "%s/a.db", dir);
    static web_store_t st;
    WT_EQ(web_store_open(&st, p, err, sizeof(err)), 0);
    WT_EQ(web_rollup_init(&ru, 256, 0, e2, sizeof(e2)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, &st, 30, 256, NULL, NULL), 0);
    enum { NB = 8640, NK = 32 };
    static web_qrow_t r[NB];
    for (int i = 0; i < NK; i++) {
        for (int b = 0; b < NB; b++) {
            memset(&r[b], 0, sizeof(r[b]));
            r[b].tier = WEB_TIER_FINE;
            r[b].metric = WM_HOST_RX;
            snprintf(r[b].key, sizeof(r[b].key), "10.0.4.%d", i + 1);
            r[b].t = T + (long long)b * 10;
            r[b].sum = r[b].min = r[b].max = 1 + (b + i) % 97;
            r[b].n = 1;
        }
        WT_EQ(web_store_write(&st, r, NB), 0);
        /* The key is the rollup's too: the route lists the rollup's keys. */
        snprintf(qs, sizeof(qs), "10.0.4.%d", i + 1);
        web_rollup_add(&ru, WM_HOST_RX, qs, 1, T + 86400);
    }
    snprintf(qs, sizeof(qs), "metric=host.rx_rate&cols=480&from=%lld&to=%lld", T, T + 86400);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    size_t n = answer(qs, 1);
    double ms = ms_since(&t0);
    WT_ASSERT(n > 0);
    WT_HAS(body, "\"cell\":180,\"cells\":480,");
    WT_HAS(body, "\"source\":\"store+memory\"}\n");
    static char a[64][WEB_KEY_MAX + 1];
    int na = keys_of(body, a, 64);
    fprintf(stderr, "  /api/series/all, store: %d keys of %d rows in 480 cells, %zu bytes, "
            "%.1f ms (budget %d ms)\n", na, NB, n, ms,
            WEB_SDB_HTTP_MS * web_sdb_test_budget_scale);
    WT_ASSERT(na >= 7);
    WT_ASSERT(ms < (double)WEB_SDB_HTTP_MS * web_sdb_test_budget_scale);
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    web_store_close(&st);
    unlink(p);
    char s2[160];
    snprintf(s2, sizeof(s2), "%s-wal", p); unlink(s2);
    snprintf(s2, sizeof(s2), "%s-shm", p); unlink(s2);
    rmdir(dir);
}

static web_store_t g_st;
static char g_stp[128], g_stdir[TEST_TMP_MAX];
static void store_tsdb(int max_keys) {
    char err[512], e2[64];
    test_tmp_path(g_stdir, sizeof(g_stdir), "slothweb-allkeys-XXXXXX");
    WT_ASSERT(mkdtemp(g_stdir) != NULL);
    snprintf(g_stp, sizeof(g_stp), "%s/k.db", g_stdir);
    WT_EQ(web_store_open(&g_st, g_stp, err, sizeof(err)), 0);
    WT_EQ(web_rollup_init(&ru, max_keys, 0, e2, sizeof(e2)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, &g_st, 30, 256, NULL, NULL), 0);
}
static void store_done(void) {
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    web_store_close(&g_st);
    unlink(g_stp);
    char s2[160];
    snprintf(s2, sizeof(s2), "%s-wal", g_stp); unlink(s2);
    snprintf(s2, sizeof(s2), "%s-shm", g_stp); unlink(s2);
    rmdir(g_stdir);
}
static void store_row(web_qrow_t *r, int metric, const char *key, long long t, double v) {
    memset(r, 0, sizeof(*r));
    r->tier = WEB_TIER_FINE;
    r->metric = metric;
    snprintf(r->key, sizeof(r->key), "%s", key);
    r->t = t;
    r->sum = r->min = r->max = v;
    r->n = 1;
}

/* The keys are the rollup's and the store's: a key the rollup has
 * evicted, or never held in this run, is answered from its rows when it
 * has one in the window, and is not when it has none there. */
static void test_keys_are_the_stores_too(void) {
    store_tsdb(64);
    web_qrow_t r[4];
    store_row(&r[0], WM_HOST_RX, "10.0.5.2", T + 20, 7);          /* in the window */
    store_row(&r[1], WM_HOST_RX, "10.0.5.9", T - 86400, 9);       /* before it */
    store_row(&r[2], WM_HOST_TX, "10.0.5.4", T + 20, 3);          /* another metric */
    store_row(&r[3], WM_HOST_RX, "10.0.5.1", T + 30, 5);          /* the rollup's too */
    WT_EQ(web_store_write(&g_st, r, 4), 0);
    web_rollup_add(&ru, WM_HOST_RX, "10.0.5.1", 5, T + 30);
    web_rollup_add(&ru, WM_HOST_RX, "10.0.5.3", 4, T + 40);       /* the rollup's alone */
    char qs[200];
    snprintf(qs, sizeof(qs), "metric=host.rx_rate&cols=8&from=%lld&to=%lld", T, T + 80);
    WT_ASSERT(answer(qs, 1) > 0);
    WT_HAS(body, "\"total\":3,\"keys\":[{\"key\":\"10.0.5.1\",\"p\":[3,5]},"
                 "{\"key\":\"10.0.5.2\",\"p\":[2,7]},{\"key\":\"10.0.5.3\",\"p\":[4,4]}]");
    WT_LACKS(body, "10.0.5.9");
    WT_LACKS(body, "10.0.5.4");
    WT_LACKS(body, "total_min");
    /* The store's own list, in byte order, after a key, to a limit. */
    static char ks[8][WEB_KEY_MAX + 1];
    WT_EQ(web_store_keys_after(&g_st, WEB_TIER_FINE, WM_HOST_RX, T, T + 80, NULL, ks, 8), 2);
    WT_ASSERT(!strcmp(ks[0], "10.0.5.1") && !strcmp(ks[1], "10.0.5.2"));
    WT_EQ(web_store_keys_after(&g_st, WEB_TIER_FINE, WM_HOST_RX, T, T + 80, "10.0.5.1", ks, 8), 1);
    WT_ASSERT(!strcmp(ks[0], "10.0.5.2"));
    WT_EQ(web_store_keys_after(&g_st, WEB_TIER_FINE, WM_HOST_RX, T, T + 80, NULL, ks, 1), 1);
    WT_EQ(web_store_keys_after(&g_st, WEB_TIER_FINE, WM_HOST_RX, T - 90000, T + 80, NULL, ks, 8), 3);
    WT_EQ(web_store_keys_after(&g_st, WEB_TIER_MINUTE, WM_HOST_RX, T, T + 80, NULL, ks, 8), 0);
    /* A global metric's one key is "", which the first read must not
     * pass over. */
    store_row(&r[0], WM_CONNS_TOTAL, "", T + 20, 12);
    WT_EQ(web_store_write(&g_st, r, 1), 0);
    WT_EQ(web_store_keys_after(&g_st, WEB_TIER_FINE, WM_CONNS_TOTAL, T, T + 80, NULL, ks, 8), 1);
    WT_ASSERT(ks[0][0] == '\0');
    snprintf(qs, sizeof(qs), "metric=conns.total&cols=8&from=%lld&to=%lld", T, T + 80);
    WT_ASSERT(answer(qs, 1) > 0);
    WT_HAS(body, "\"total\":1,\"keys\":[{\"key\":\"\",\"p\":[2,12]}]");
    store_done();
}

/* And from the store: 8,192 keys the rollup no longer holds, 8 rows
 * each, every key walked; the first answer counts them all. */
static void test_walk_of_8192_keys_from_the_store(void) {
    store_tsdb(64);
    enum { NK = 8192, NB = 8 };
    static web_qrow_t r[NK];
    char k[32], qs[200];
    for (int b = 0; b < NB; b++) {
        for (int i = 0; i < NK; i++) {
            snprintf(k, sizeof(k), "02:00:00:00:%02x:%02x", i / 256, i % 256);
            store_row(&r[i], WM_DEV_FRAMES, k, T + (long long)b * 450, 1 + (b + i) % 7);
        }
        WT_EQ(web_store_write(&g_st, r, NK), 0);
    }
    snprintf(qs, sizeof(qs), "metric=dev.frames&cols=64&from=%lld&to=%lld", T, T + 3600);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    size_t n = answer(qs, 1);
    double first = ms_since(&t0);
    WT_ASSERT(n > 0);
    WT_HAS(body, "\"total\":8192,\"keys\":[");
    walk_t w = walk(qs, 1);
    fprintf(stderr, "  /api/series/all, store: %d keys walked in %d answers, %zu bytes, "
            "%.0f ms in all, the slowest answer %.1f ms, the first (it counts the keys) %.1f ms "
            "(budget %d ms)\n", w.keys, w.pages, w.bytes, w.all_ms, w.worst_ms, first,
            WEB_SDB_HTTP_MS * web_sdb_test_budget_scale);
    WT_EQ(w.keys, NK);
    WT_EQ(w.total, NK);
    WT_EQ(w.dups, 0);
    WT_ASSERT(w.worst_ms < (double)WEB_SDB_HTTP_MS * web_sdb_test_budget_scale);
    store_done();
}
#endif

/* ── the page's pure half, ported ───────────────────────────────── */

/* The JS, verbatim (web/ui/allkeys.js): begin. */
static const char JS_RANK[] =
    "  function rank(rows) {\n"
    "    var out = (rows || []).slice();\n"
    "    out.sort(function (a, b) {\n"
    "      var na = gnum(a.cur), nb = gnum(b.cur);\n"
    "      if (na !== nb) return na ? -1 : 1;\n"
    "      if (na && a.cur !== b.cur) return b.cur - a.cur;\n"
    "      return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;\n"
    "    });\n"
    "    return out;\n"
    "  }";

static const char JS_KEYSTEXT[] =
    "  function keysText(shown, total, cut, min, loading) {\n"
    "    var of = gnum(total) ? \" of \" + total + (min ? \"+\" : \"\") : \"\";\n"
    "    if (loading) return \"loading \" + shown + of + \" keys\";\n"
    "    if (cut === \"bound\") return shown + of + \" keys, the first by key (the graph holds \" + shown + \")\";\n"
    "    if (cut === \"time\") return shown + of + \" keys (the read was stopped at 60 s)\";\n"
    "    if (cut === \"stopped\") return shown + of + \" keys (the read stopped)\";\n"
    "    return shown + (shown === 1 ? \" key\" : \" keys\");\n"
    "  }";

static const char JS_TIEROF[] =
    "  function tierOf(win, storeOn) {\n"
    "    if (!storeOn || win <= 86400) return [\"fine\", 10, win > 86400 ? 86400 : win];\n"
    "    if (win <= BUCKETS * 60) return [\"minute\", 60, win];\n"
    "    return [\"hour\", 3600, win > BUCKETS * 3600 ? BUCKETS * 3600 : win];\n"
    "  }";

static const char JS_COLSFOR[] =
    "  function colsFor(total, plot, points, max, least) {\n"
    "    var n = total > max ? max : total;\n"
    "    if (!(n > 0) || n * plot <= points) return plot;\n"
    "    var c = Math.floor(points / n);\n"
    "    return c < least ? least : c;\n"
    "  }";

static const char JS_FILTERROWS[] =
    "  function filterRows(rows, q) {\n"
    "    var out = [], i;\n"
    "    q = q.toLowerCase();\n"
    "    for (i = 0; i < rows.length; i++)\n"
    "      if (q === \"\" || rows[i].key.toLowerCase().indexOf(q) >= 0) out.push(i);\n"
    "    return out;\n"
    "  }";

static const char JS_STRIPROW[] =
    "  function stripRow(n) {\n"
    "    if (n <= 512) return [8, 6, 5];\n"
    "    if (n <= 1024) return [4, 2, 10];\n"
    "    if (n <= 4096) return [2, 2, 50];\n"
    "    return [1, 1, 100];\n"
    "  }";

static const char JS_LINES[] =
    "  function lines(rows, opt) {\n"
    "    var m = [], w = opt.w, h = opt.h, i, j, n;\n"
    "    var x0 = opt.padL, x1 = w - opt.padR, y0 = opt.padT, y1 = h - opt.padB;\n"
    "    var any = false;\n"
    "    for (i = 0; i < rows.length; i++) if (rows[i].pts.length) any = true;\n"
    "    if (!any) { m.push([\"dash\", w * 0.35, h / 2, w * 0.3, 1, \"--faint\"]); return m; }\n"
    "    var from = opt.from, to = opt.to, lo = opt.scale[0], hi = opt.scale[1];\n"
    "    var X = function (t) { return to > from ? x0 + (t - from) / (to - from) * (x1 - x0) : x0; };\n"
    "    var Y = function (v) { return y1 - (v - lo) / (hi - lo) * (y1 - y0); };\n"
    "    var focus = opt.hot >= 0 ? opt.hot : opt.pick;\n"
    "    var gap = opt.step * GAP_STEPS;\n"
    "    var bp = opt.band && opt.pick >= 0 && opt.pick < rows.length ? rows[opt.pick].pts : null;\n"
    "    for (i = 0; bp && i < bp.length; i++) {\n"
    "      var b = opt.band[i];\n"
    "      if (!b) continue;\n"
    "      var bx = X(bp[i][0]);\n"
    "      var bw = Math.min(Math.max(1, X(bp[i][0] + opt.step) - bx), Math.max(0, x1 - bx));\n"
    "      if (bw > 0) m.push([\"band\", bx, Y(b[1]), bw, Y(b[0]) - Y(b[1]), \"--data\"]);\n"
    "    }\n"
    "    // The rows past opt.lines, but the focus: the least and the most of\n"
    "    // them in each cell, one range mark a cell, under every line.\n"
    "    var rl = [], rh = [], c, p;\n"
    "    for (i = opt.lines; i < rows.length; i++) {\n"
    "      if (i === focus) continue;\n"
    "      p = rows[i].pts;\n"
    "      for (j = 0; j < p.length; j++) {\n"
    "        c = Math.round((p[j][0] - opt.t0) / opt.step);\n"
    "        if (c < 0) continue;\n"
    "        if (rl[c] === undefined || p[j][1] < rl[c]) rl[c] = p[j][1];\n"
    "        if (rh[c] === undefined || p[j][1] > rh[c]) rh[c] = p[j][1];\n"
    "      }\n"
    "    }\n"
    "    for (c = 0; c < rl.length; c++) {\n"
    "      if (rl[c] === undefined) continue;\n"
    "      var ex = X(opt.t0 + c * opt.step);\n"
    "      var ew = Math.min(Math.max(1, X(opt.t0 + (c + 1) * opt.step) - ex), Math.max(0, x1 - ex));\n"
    "      if (ew > 0 && ex >= x0) m.push([\"range\", ex, Y(rh[c]), ew, Math.max(1, Y(rl[c]) - Y(rh[c])), DIM]);\n"
    "    }\n"
    "    for (n = rows.length < opt.lines ? rows.length : opt.lines; n >= 0; n--) {\n"
    "      i = n > 0 ? n - 1 : focus;\n"
    "      if (i < 0 || (n > 0 && i === focus)) continue;\n"
    "      p = rows[i].pts;\n"
    "      if (!p.length) continue;\n"
    "      var tok = focus >= 0 && i !== focus ? DIM : \"--k-\" + rows[i].k;\n"
    "      var dots = p.length < DOTS_BELOW;\n"
    "      for (j = 0; j < p.length; j++) {\n"
    "        var left = j > 0 && p[j][0] - p[j - 1][0] <= gap;\n"
    "        var right = j + 1 < p.length && p[j + 1][0] - p[j][0] <= gap;\n"
    "        if (j > 0 && !left)\n"
    "          m.push([\"gap\", X(p[j - 1][0]), y0, X(p[j][0]) - X(p[j - 1][0]), y1 - y0, \"--faint\"]);\n"
    "        if (left && !dots)\n"
    "          m.push([\"line\", X(p[j - 1][0]), Y(p[j - 1][1]), X(p[j][0]) - X(p[j - 1][0]),\n"
    "                  Y(p[j][1]) - Y(p[j - 1][1]), tok]);\n"
    "        // A point no line reaches is a dot, or it would not be drawn.\n"
    "        if ((dots || (!left && !right)) && j < p.length - 1)\n"
    "          m.push([\"dot\", X(p[j][0]), Y(p[j][1]), 1.5, 1.5, tok]);\n"
    "      }\n"
    "      m.push([\"last\", X(p[p.length - 1][0]), Y(p[p.length - 1][1]), 2.5, 2.5, tok]);\n"
    "    }\n"
    "    // The end labels: the first opt.labels rows that have a point, and\n"
    "    // the focus row whatever its rank; pushed apart top down, then the\n"
    "    // stack lifted back inside the plot.\n"
    "    var li = [], ly = [], lc = 0;\n"
    "    for (i = 0; i < rows.length && opt.padR > 8; i++) {\n"
    "      if (!rows[i].pts.length) continue;\n"
    "      if (lc >= opt.labels && i !== focus) continue;\n"
    "      lc++;\n"
    "      var y = Y(rows[i].pts[rows[i].pts.length - 1][1]);\n"
    "      for (j = li.length; j > 0 && ly[j - 1] > y; j--) { li[j] = li[j - 1]; ly[j] = ly[j - 1]; }\n"
    "      li[j] = i;\n"
    "      ly[j] = y;\n"
    "    }\n"
    "    for (j = 1; j < li.length; j++) if (ly[j] < ly[j - 1] + LABEL_GAP) ly[j] = ly[j - 1] + LABEL_GAP;\n"
    "    var over = li.length ? ly[li.length - 1] - (y1 - LABEL_H / 2) : 0;\n"
    "    for (j = 0; j < li.length; j++)\n"
    "      m.push([\"label\", x1 + 6, over > 0 ? ly[j] - over : ly[j], opt.padR - 8, LABEL_H,\n"
    "              focus >= 0 && li[j] !== focus ? DIM : \"--k-\" + rows[li[j]].k, rows[li[j]].label]);\n"
    "    return m;\n"
    "  }";

static const char JS_FRAME[] =
    "  function frame(opt) {\n"
    "    var m = [], w = opt.w, h = opt.h;\n"
    "    var x0 = opt.padL, x1 = w - opt.padR, y0 = opt.padT, y1 = h - opt.padB;\n"
    "    m.push([\"axis\", x0, y0, x1 - x0, 1, \"--rule\"]);\n"
    "    m.push([\"axis\", x0, y1, x1 - x0, 1, \"--rule\"]);\n"
    "    m.push([\"num\", 2, y0 + 5, x0 - 6, 10, \"--muted\", opt.ytop]);\n"
    "    m.push([\"num\", 2, y1 - 5, x0 - 6, 10, \"--muted\", opt.ybot]);\n"
    "    m.push([\"num\", x0, h - 6, 96, 10, \"--muted\", opt.xt[0]]);\n"
    "    m.push([\"num\", (x0 + x1) / 2 - 24, h - 6, 96, 10, \"--muted\", opt.xt[1]]);\n"
    "    m.push([\"num\", x1 - 48, h - 6, 96, 10, \"--muted\", opt.xt[2]]);\n"
    "    if (opt.to > opt.from && opt.now >= opt.from && opt.now <= opt.to)\n"
    "      m.push([\"now\", x0 + (opt.now - opt.from) / (opt.to - opt.from) * (x1 - x0), y0, 1, y1 - y0, \"--signal\"]);\n"
    "    return m;\n"
    "  }";

static const char JS_STRIPS[] =
    "  function strips(rows, opt) {\n"
    "    var m = [], x0 = opt.padL, pw = opt.w - opt.padL - opt.padR, rh = opt.rowH, i, j;\n"
    "    var any = false;\n"
    "    for (i = 0; i < rows.length; i++) if (rows[i].cells.length) any = true;\n"
    "    if (!any) {\n"
    "      m.push([\"dash\", opt.w * 0.35, Math.max(1, rows.length) * rh / 2, opt.w * 0.3, 1, \"--faint\"]);\n"
    "      return m;\n"
    "    }\n"
    "    var focus = opt.hot >= 0 ? opt.hot : opt.pick;\n"
    "    for (i = 0; i < rows.length; i++) {\n"
    "      var c = rows[i].cells, y = i * rh;\n"
    "      var tok = focus >= 0 && i !== focus ? DIM : \"--k-\" + rows[i].k;\n"
    "      if (i === 0 || (i + 1) % opt.every === 0)\n"
    "        m.push([\"num\", 2, y + rh / 2, x0 - 4, 8, \"--muted\", String(i + 1)]);\n"
    "      for (j = 0; j < c.length; j++) {\n"
    "        var a = c[j], e = a;\n"
    "        while (j + 1 < c.length && c[j + 1] === e + 1) { j++; e++; }\n"
    "        m.push([\"cell\", x0 + a / opt.ncell * pw, y, Math.max(1, (e + 1 - a) / opt.ncell * pw), opt.ink, tok]);\n"
    "      }\n"
    "    }\n"
    "    var ty = rows.length * rh + 8;\n"
    "    m.push([\"num\", x0, ty, 96, 10, \"--muted\", opt.xt[0]]);\n"
    "    m.push([\"num\", x0 + pw / 2 - 24, ty, 96, 10, \"--muted\", opt.xt[1]]);\n"
    "    m.push([\"num\", x0 + pw - 48, ty, 96, 10, \"--muted\", opt.xt[2]]);\n"
    "    return m;\n"
    "  }";

static const char JS_PAINTMARKS[] =
    "  function paintMarks(c, marks, resolve) {\n"
    "    var dpr = window.devicePixelRatio || 1;\n"
    "    var w = Math.max(1, Math.round(c.clientWidth * dpr));\n"
    "    var h = Math.max(1, Math.round(c.clientHeight * dpr));\n"
    "    if (c.width !== w) c.width = w;\n"
    "    if (c.height !== h) c.height = h;\n"
    "    var g = c.getContext(\"2d\"), open = null;\n"
    "    g.clearRect(0, 0, w, h);\n"
    "    g.lineWidth = Math.max(1, dpr);\n"
    "    for (var i = 0; i < marks.length; i++) {\n"
    "      var m = marks[i], k = m[0];\n"
    "      if (k === \"gap\") continue;\n"
    "      if (k === \"line\") {\n"
    "        if (open !== m[5]) {\n"
    "          if (open !== null) g.stroke();\n"
    "          open = m[5];\n"
    "          g.strokeStyle = resolve(open);\n"
    "          g.beginPath();\n"
    "        }\n"
    "        g.moveTo(m[1] * dpr, m[2] * dpr);\n"
    "        g.lineTo((m[1] + m[3]) * dpr, (m[2] + m[4]) * dpr);\n"
    "        continue;\n"
    "      }\n"
    "      if (open !== null) { g.stroke(); open = null; }\n"
    "      g.fillStyle = resolve(m[5]);\n"
    "      if (typeof m[6] === \"string\") {\n"
    "        g.font = Math.round(m[4] * dpr) + \"px \" + resolve(\"--font-mono\");\n"
    "        g.textBaseline = \"middle\";\n"
    "        g.textAlign = \"left\";\n"
    "        g.fillText(m[6], m[1] * dpr, m[2] * dpr, Math.max(1, m[3] * dpr));\n"
    "      } else if (k === \"band\" || k === \"range\") {\n"
    "        g.globalAlpha = k === \"band\" ? 0.12 : 0.35;\n"
    "        g.fillRect(m[1] * dpr, m[2] * dpr, Math.max(1, m[3] * dpr), Math.max(1, m[4] * dpr));\n"
    "        g.globalAlpha = 1;\n"
    "      } else if (k === \"dot\" || k === \"last\") {\n"
    "        g.beginPath();\n"
    "        g.arc(m[1] * dpr, m[2] * dpr, Math.max(1, m[3] * dpr), 0, 6.283185307179586);\n"
    "        g.fill();\n"
    "      } else {\n"
    "        g.fillRect(m[1] * dpr, m[2] * dpr, Math.max(1, m[3] * dpr), Math.max(1, m[4] * dpr));\n"
    "      }\n"
    "    }\n"
    "    if (open !== null) g.stroke();\n"
    "  }";

static const char JS_MODEBTN[] =
    "  function modeBtn() {\n"
    "    $(\"ak-mode\").ariaPressed = S.on ? \"true\" : \"false\";\n"
    "    H.set(\"ak-mode\", S.on ? \"keys: all\" : \"keys: one\");\n"
    "  }";

static const char JS_ROWOF[] =
    "  function rowOf(k, head, presence) {\n"
    "    var pts = [], cells = [], p = k.p;\n"
    "    for (var i = 0; i + 1 < p.length; i += 2) {\n"
    "      if (!gnum(p[i]) || !gnum(p[i + 1])) continue;\n"
    "      pts.push([head.from + p[i] * head.cell, p[i + 1]]);\n"
    "      if (p[i + 1] >= 0.5) cells.push(p[i]);\n"
    "    }\n"
    "    return { key: k.key, k: H.colorIndex(k.key), pts: pts, cells: cells, band: null,\n"
    "             cur: presence ? (cells.length ? cells.length : null)\n"
    "                           : pts.length ? pts[pts.length - 1][1] : null };\n"
    "  }";

static const char JS_INDEXOFKEY[] =
    "  function indexOfKey(key) {\n"
    "    if (key === null) return -1;\n"
    "    for (var i = 0; i < S.rows.length; i++) if (S.rows[i].key === key) return i;\n"
    "    return -1;\n"
    "  }";

static const char JS_WANTBAND[] =
    "  function wantBand(m) {\n"
    "    if (indexOfKey(S.pick) < 0 || !S.got || S.got.head.kind === \"presence\") return;\n"
    "    var of = m.name + \"\\u0000\" + S.pick + \"\\u0000\" + H.scope();\n"
    "    if (S.blOf === of) return;\n"
    "    S.blOf = of;\n"
    "    S.bl = null;\n"
    "    H.baseline(m.name, S.pick).then(function (bl) {\n"
    "      if (S.blOf !== of) return;\n"
    "      S.bl = bl;\n"
    "      paint(m);\n"
    "    });\n"
    "  }";

static const char JS_LEGEND[] =
    "  function legend(m) {\n"
    "    var box = $(\"ak-legend\"), head = S.got ? S.got.head : null;\n"
    "    var presence = !!head && head.kind === \"presence\";\n"
    "    var hits = filterRows(S.rows, S.filter), n = Math.min(hits.length, S.shown);\n"
    "    while (box.firstChild) box.removeChild(box.firstChild);\n"
    "    S.lkeys = [];\n"
    "    hits.slice(0, n).forEach(function (i) {\n"
    "      var r = S.rows[i];\n"
    "      var row = H.el(\"div\", \"ak-row\");\n"
    "      row.role = \"listitem\";\n"
    "      var b = H.el(\"button\", \"ak-key\" + (S.pick === r.key ? \" on\" : \"\"));\n"
    "      b.type = \"button\";\n"
    "      b.ariaPressed = S.pick === r.key ? \"true\" : \"false\";\n"
    "      b.title = \"show this key alone in its colour, the rest grey; again for every key\";\n"
    "      b.appendChild(H.el(\"span\", \"ak-rank\", String(i + 1)));\n"
    "      var sw = H.el(\"span\", \"sw\");\n"
    "      sw.style.background = \"var(--k-\" + r.k + \")\";\n"
    "      b.appendChild(sw);\n"
    "      b.appendChild(r.key ? H.keySpan(r.key) : H.el(\"span\", \"d-normal\", \"(global)\"));\n"
    "      b.appendChild(H.el(\"span\", \"ak-v\", r.cur === null ? \"-\"\n"
    "        : presence ? r.cur + \"/\" + head.cells + \" cells\"\n"
    "        : H.fmt(r.cur) + \" \" + m.unit));\n"
    "      b.addEventListener(\"click\", function () { pick(m, S.pick === r.key ? null : r.key); });\n"
    "      b.addEventListener(\"mouseenter\", function () { hot(m, r.key); });\n"
    "      b.addEventListener(\"mouseleave\", function () { hot(m, null); });\n"
    "      b.addEventListener(\"focus\", function () { hot(m, r.key); });\n"
    "      b.addEventListener(\"blur\", function () { hot(m, null); });\n"
    "      row.appendChild(b);\n"
    "      // A device has a drawer: the page's own way into it.\n"
    "      if (H.isMac(r.key)) {\n"
    "        var o = H.el(\"button\", \"dt-reset ak-open\", \"device\");\n"
    "        o.type = \"button\";\n"
    "        o.title = \"open this device\";\n"
    "        o.addEventListener(\"click\", function () { H.openDrawer(r.key); });\n"
    "        row.appendChild(o);\n"
    "      }\n"
    "      box.appendChild(row);\n"
    "      S.lkeys.push(r.key);\n"
    "    });\n"
    "    $(\"ak-all\").hidden = S.pick === null;\n"
    "    $(\"ak-filter\").hidden = S.rows.length <= 8 && S.filter === \"\";\n"
    "    $(\"ak-more\").hidden = n >= hits.length;\n"
    "    H.set(\"ak-more\", \"show \" + Math.min(LEGEND_CHUNK, hits.length - n) + \" more\");\n"
    "    H.set(\"ak-rule\", !S.rows.length ? \"\"\n"
    "      : (presence ? \"every key by the cells it was present in, most first\"\n"
    "                  : \"every key by its latest value, largest first\") +\n"
    "        \"; equal values by key. Pick one to show it alone; Esc or the same entry again for all.\" +\n"
    "        (n < S.rows.length ? \" Listed: \" + n + \" of \" +\n"
    "          (S.filter === \"\" ? S.rows.length : hits.length + \" matching, of \" + S.rows.length) + \".\"\n"
    "                           : \"\"));\n"
    "  }";

static const char JS_PICK[] =
    "  function pick(m, key) {\n"
    "    S.pick = key;\n"
    "    // The key picker follows, when the key is one of its 256.\n"
    "    S.pickOut = false;\n"
    "    if (key !== null) { S.pickOut = !H.pickKey(key); S.lastKey = H.key(); }\n"
    "    var bs = $(\"ak-legend\").querySelectorAll(\"button.ak-key\");\n"
    "    for (var i = 0; i < bs.length && i < S.lkeys.length; i++) {\n"
    "      var on = S.lkeys[i] === key;\n"
    "      bs[i].classList.toggle(\"on\", on);\n"
    "      bs[i].ariaPressed = on ? \"true\" : \"false\";\n"
    "    }\n"
    "    $(\"ak-all\").hidden = key === null;\n"
    "    wantBand(m);\n"
    "    paint(m);\n"
    "  }";

static const char JS_HOT[] =
    "  function hot(m, key) {\n"
    "    if (S.hot === key) return;\n"
    "    S.hot = key;\n"
    "    if (S.raf) return;\n"
    "    S.raf = window.requestAnimationFrame(function () { S.raf = 0; paint(m); });\n"
    "  }";

static const char JS_STAMP[] =
    "  function stamp(t, win) {\n"
    "    if (win <= 86400) return H.hhmmss(t).slice(0, 5);\n"
    "    var d = new Date(t * 1000);\n"
    "    function two(n) { return (n < 10 ? \"0\" : \"\") + n; }\n"
    "    return two(d.getMonth() + 1) + \"-\" + two(d.getDate()) + \" \" + two(d.getHours()) + \":00\";\n"
    "  }";

static const char JS_ISBANDED[] =
    "  function isBanded(band) {\n"
    "    for (var i = 0; band && i < band.length; i++) if (band[i]) return true;\n"
    "    return false;\n"
    "  }";

static const char JS_PAINT[] =
    "  function paint(m) {\n"
    "    var g = S.got;\n"
    "    if (!S.on || !g) return;\n"
    "    var head = g.head, cv = $(\"ak-chart\"), presence = head.kind === \"presence\";\n"
    "    var pi = indexOfKey(S.pick), hi = indexOfKey(S.hot), pn = 0, i;\n"
    "    // The band is the picked key's alone, at the slider's k as it is now.\n"
    "    var band = pi >= 0 && !presence && S.bl && S.blOf === m.name + \"\\u0000\" + S.pick + \"\\u0000\" + H.scope()\n"
    "      ? H.bands(S.rows[pi].pts, S.bl, head.kind, head.cell) : null;\n"
    "    // R5: an empty panel collapses to its caption.\n"
    "    cv.hidden = !S.rows.length;\n"
    "    for (i = 0; i < S.rows.length; i++) pn += S.rows[i].pts.length;\n"
    "    var win = head.to - head.from, marks, scaleText;\n"
    "    var keys = keysText(S.rows.length, g.total, g.cut, g.min, S.loading && !S.done);\n"
    "    if (presence) {\n"
    "      var sr = stripRow(S.rows.length);\n"
    "      cv.style.height = Math.max(3, S.rows.length) * sr[0] + PAD_B + \"px\";\n"
    "      var so = { w: cv.clientWidth, rowH: sr[0], ink: sr[1], every: sr[2], padL: 28, padR: 4,\n"
    "                 ncell: head.cells, pick: pi, hot: hi,\n"
    "                 xt: [stamp(head.from, win), stamp((head.from + head.to) / 2, win), stamp(head.to, win)] };\n"
    "      marks = strips(S.rows, so);\n"
    "      S.view = { presence: true, o: so };\n"
    "      scaleText = pn ? \"0/1, one row a key, sorted by cells present\" : \"\";\n"
    "    } else {\n"
    "      cv.style.height = \"\";\n"
    "      // R11: the shared scale grows and never shrinks on a refresh; a\n"
    "      // new metric, scope or window starts it again. R4: a window the\n"
    "      // data covers under a tenth of is drawn as the data's own.\n"
    "      var lo = 0, hi2 = 0, t0 = null, t1 = null;\n"
    "      var sc = glyph.shared(S.rows, S.scaleOf === S.of ? S.scale : null);\n"
    "      if (band) sc = glyph.scale(S.rows[pi].pts, band, sc);\n"
    "      S.scale = sc;\n"
    "      S.scaleOf = S.of;\n"
    "      lo = sc[0];\n"
    "      hi2 = sc[1];\n"
    "      for (i = 0; i < S.rows.length; i++) {\n"
    "        var p = S.rows[i].pts;\n"
    "        if (!p.length) continue;\n"
    "        if (t0 === null || p[0][0] < t0) t0 = p[0][0];\n"
    "        if (t1 === null || p[p.length - 1][0] > t1) t1 = p[p.length - 1][0];\n"
    "      }\n"
    "      var gw = glyph.win(t0 === null ? [] : [[t0, 0], [t1, 0]], head.from, head.to);\n"
    "      var o = { w: cv.clientWidth, h: cv.clientHeight, padL: PAD_L, padR: PAD_R, padT: PAD_T, padB: PAD_B,\n"
    "                from: gw.from, to: gw.to, step: head.cell, t0: head.from, scale: [lo, hi2], pick: pi, hot: hi,\n"
    "                labels: LABELS, lines: LINES, band: band, now: Date.now() / 1000,\n"
    "                ytop: H.fmt(hi2), ybot: H.fmt(lo),\n"
    "                xt: [stamp(gw.from, win), stamp((gw.from + gw.to) / 2, win), stamp(gw.to, win)] };\n"
    "      for (i = 0; i < S.rows.length; i++)\n"
    "        S.rows[i].label = (i + 1) + \" \" + (S.rows[i].key || \"(global)\");\n"
    "      marks = frame(o).concat(lines(S.rows, o));\n"
    "      S.view = { presence: false, o: o };\n"
    "      var banded = isBanded(band);\n"
    "      scaleText = !pn ? \"\" : \"shared scale, top \" + H.fmt(hi2) + \" \" + m.unit + \", \" +\n"
    "        (banded ? \"band ±\" + H.sens().toFixed(1) + \" sd for \" + S.pick\n"
    "                : pi >= 0 ? \"no band for \" + S.pick + \" yet\"\n"
    "                : \"no band: it is one key's, pick a key for its\") +\n"
    "        \", sorted by latest value\" +\n"
    "        (S.rows.length > LINES ? \", lines for the \" + LINES + \" largest, the other \" +\n"
    "                                 (S.rows.length - LINES) + \" as their range a cell\" : \"\");\n"
    "      S.shrunk = gw.shrunk ? gw.text : \"\";\n"
    "    }\n"
    "    paintMarks(cv, marks, H.tok);\n"
    "    var cellWord = head.cell === head.step ? head.tier\n"
    "      : head.tier + \" in \" + glyph.dur(head.cell) + \" cells (\" +\n"
    "        (head.kind === \"counter\" ? \"sum\" : head.kind === \"presence\" ? \"any\" : \"mean\") + \")\";\n"
    "    H.set(\"a-title\", m.name + \"  every key  (\" + m.unit + \")\");\n"
    "    H.set(\"a-src\", glyph.caption({\n"
    "      source: m.name + \", \" + keys + \", \" + head.source,\n"
    "      window: glyph.dur(win), tier: cellWord, scale: scaleText, n: pn,\n"
    "      state: head.out_of_scope === true ? \"not in the \" + H.scopeWord(H.scope()) + \" scope\"\n"
    "           : !S.rows.length ? (S.loading && !S.done ? \"\" : \"no \" + (head.keykind || \"key\") + \" seen yet\")\n"
    "           : !pn ? \"no data\"\n"
    "           : !presence && S.shrunk ? S.shrunk\n"
    "           : !presence && pi >= 0 && !isBanded(band) ? \"warming\" : \"\" }) +\n"
    "      (S.pickOut && S.pick !== null ? \"; \" + S.pick + \" is not one of the key picker's 256\" : \"\") +\n"
    "      (S.clamped ? \"; minute and hour tiers need a WITH_SQLITE build\" : \"\"));\n"
    "  }";

static const char JS_ROWAT[] =
    "  function rowAt(x, y) {\n"
    "    var v = S.view, i;\n"
    "    if (!v) return -1;\n"
    "    if (v.presence) {\n"
    "      i = Math.floor(y / v.o.rowH);\n"
    "      return i >= 0 && i < S.rows.length ? i : -1;\n"
    "    }\n"
    "    var o = v.o, x0 = o.padL, x1 = o.w - o.padR, y0 = o.padT, y1 = o.h - o.padB;\n"
    "    if (x < x0 || x > x1 || !(o.to > o.from)) return -1;\n"
    "    var t = o.from + (x - x0) / (x1 - x0) * (o.to - o.from), best = -1, bd = 12;\n"
    "    for (i = 0; i < S.rows.length; i++) {\n"
    "      var p = S.rows[i].pts, a = 0, b = p.length - 1;\n"
    "      // A row folded into the range has no line to point at.\n"
    "      if (!p.length || (i >= o.lines && i !== o.pick)) continue;\n"
    "      while (a < b) { var mid = (a + b) >> 1; if (p[mid][0] < t) a = mid + 1; else b = mid; }\n"
    "      if (a > 0 && t - p[a - 1][0] < p[a][0] - t) a--;\n"
    "      if (Math.abs(p[a][0] - t) > o.step * GAP_STEPS) continue;\n"
    "      var d = Math.abs(y1 - (p[a][1] - o.scale[0]) / (o.scale[1] - o.scale[0]) * (y1 - y0) - y);\n"
    "      if (d < bd) { bd = d; best = i; }\n"
    "    }\n"
    "    return best;\n"
    "  }";

static const char JS_TAKE[] =
    "  function take(R, j) {\n"
    "    var ks = j.keys || [], presence = R.head.kind === \"presence\";\n"
    "    for (var i = 0; i < ks.length && R.rows.length < KEYS_MAX; i++)\n"
    "      if (ks[i] && typeof ks[i].key === \"string\" && Array.isArray(ks[i].p))\n"
    "        R.rows.push(rowOf(ks[i], R.head, presence));\n"
    "  }";

static const char JS_LAND[] =
    "  function land(m, R, done, cut) {\n"
    "    S.got = { head: R.head, total: R.total, min: R.min, cut: cut };\n"
    "    S.rows = rank(R.rows);\n"
    "    S.done = done;\n"
    "    if (done) {\n"
    "      S.loading = false;\n"
    "      S.at = Date.now();\n"
    "      S.took = S.at - R.t0;\n"
    "    }\n"
    "    if (indexOfKey(S.pick) < 0) { S.pick = null; S.pickOut = false; }\n"
    "    S.hot = null;\n"
    "    legend(m);\n"
    "    wantBand(m);\n"
    "    paint(m);\n"
    "  }";

static const char JS_LOAD[] =
    "  function load(m) {\n"
    "    var want = Number($(\"a-win\").value) || 3600;\n"
    "    var tr = tierOf(want, H.storeOn()), tier = tr[0], step = tr[1], win = tr[2];\n"
    "    // A cell for every two pixels of the plot: the box's width, because\n"
    "    // the canvas is hidden while there is no key to draw.\n"
    "    var plot = Math.max(COLS_MIN, Math.min(COLS_MAX, Math.floor(($(\"ak-box\").clientWidth - PAD_L - PAD_R) / 2)));\n"
    "    var of = m.name + \"\\u0000\" + H.scope() + \"\\u0000\" + win + \"\\u0000\" + tier + \"\\u0000\" + plot;\n"
    "    if (S.loading && S.of === of) { paint(m); return; }\n"
    "    var every = S.got ? Math.max(Math.min(60, S.got.head.cell) * 1000 - 500, S.took * 10) : 0;\n"
    "    if (S.got && S.done && S.of === of && Date.now() - S.at < every) { paint(m); return; }\n"
    "    var now = Math.floor(Date.now() / 1000);\n"
    "    var to = now - now % step + step, from = to - win;\n"
    "    var gen = ++S.gen, first = S.of !== of || !S.done;\n"
    "    var R = { rows: [], head: null, total: null, min: false, cols: plot, t0: Date.now(), drawn: 0 };\n"
    "    if (first) {\n"
    "      S.got = null;\n"
    "      S.rows = [];\n"
    "      S.done = false;\n"
    "      S.shown = LEGEND_CHUNK;\n"
    "      legend(m);\n"
    "      H.set(\"a-title\", m.name + \"  every key  (\" + m.unit + \")\");\n"
    "      H.set(\"a-src\", m.name + \", \" + keysText(0, null, \"\", false, true));\n"
    "    }\n"
    "    S.of = of;\n"
    "    S.loading = true;\n"
    "    S.clamped = !H.storeOn() && want > 86400;\n"
    "    function page(after) {\n"
    "      var p = \"/api/series/all?metric=\" + encodeURIComponent(m.name) + \"&tier=\" + tier +\n"
    "              \"&from=\" + from + \"&to=\" + to + \"&cols=\" + R.cols;\n"
    "      if (after !== null) p += \"&after=\" + encodeURIComponent(after);\n"
    "      return H.getJSON(p).then(function (j) {\n"
    "        if (gen !== S.gen) return;\n"
    "        if (!S.on || !H.active()) { S.gen++; S.loading = false; S.done = false; return; }\n"
    "        if (after === null) {\n"
    "          R.total = gnum(j.total) ? j.total : null;\n"
    "          R.min = j.total_min === true;\n"
    "          // More cells than the graph holds: the same walk at fewer\n"
    "          // cells a key, from the start.\n"
    "          var fit = colsFor(R.total === null ? 0 : R.total, R.cols,\n"
    "                            j.kind === \"presence\" ? POINTS_STRIPS : POINTS, KEYS_MAX, COLS_MIN);\n"
    "          if (fit < R.cols) { R.cols = fit; return page(null); }\n"
    "        }\n"
    "        R.head = j;\n"
    "        take(R, j);\n"
    "        var more = j.more === true && typeof j.next === \"string\";\n"
    "        var cut = R.rows.length >= KEYS_MAX && j.more === true ? \"bound\"\n"
    "                : more && Date.now() - R.t0 >= READ_MS ? \"time\"\n"
    "                : j.more === true && !more ? \"stopped\" : \"\";\n"
    "        if (!more || cut !== \"\") { land(m, R, true, cut); return; }\n"
    "        if (first && Date.now() - R.drawn >= DRAW_MS) { R.drawn = Date.now(); land(m, R, false, \"\"); }\n"
    "        return page(j.next);\n"
    "      });\n"
    "    }\n"
    "    page(null).catch(function (e) {\n"
    "      if (gen !== S.gen) return;\n"
    "      S.loading = false;\n"
    "      H.set(\"a-src\", \"error: \" + e.message);\n"
    "    });\n"
    "  }";

static const char JS_MAIN[] =
    "  function main(m) {\n"
    "    $(\"ak-box\").hidden = !S.on;\n"
    "    $(\"a-chart\").hidden = S.on;\n"
    "    $(\"a-hover\").hidden = S.on;\n"
    "    if (!m) return false;\n"
    "    // The key picker moved, on the same metric and scope: that key is\n"
    "    // the one picked here. Another metric or scope starts with them all.\n"
    "    var k = H.key(), ctx = m.name + \"\\u0000\" + H.scope();\n"
    "    if (ctx !== S.ctx) S.pick = null;\n"
    "    else if (k !== S.lastKey && k !== \"\") S.pick = S.on ? k : null;\n"
    "    if (k !== S.lastKey || ctx !== S.ctx) S.pickOut = false;\n"
    "    S.ctx = ctx;\n"
    "    S.lastKey = k;\n"
    "    S.m = m;\n"
    "    if (!S.on) return false;\n"
    "    load(m);\n"
    "    return true;\n"
    "  }";

static const char JS_INIT[] =
    "  function init(h) {\n"
    "    H = h;\n"
    "    S.on = H.prefGet(\"act.allkeys\") === true;\n"
    "    modeBtn();\n"
    "    $(\"ak-mode\").addEventListener(\"click\", function () {\n"
    "      S.on = !S.on;\n"
    "      H.prefSet(\"act.allkeys\", S.on ? true : null);\n"
    "      modeBtn();\n"
    "      S.gen++;\n"
    "      S.loading = false;\n"
    "      if (!S.done) S.of = \"\";\n"
    "      H.redraw();\n"
    "    });\n"
    "    $(\"ak-all\").addEventListener(\"click\", function () { if (S.m) pick(S.m, null); });\n"
    "    $(\"ak-filter\").addEventListener(\"input\", function () {\n"
    "      S.filter = $(\"ak-filter\").value.trim();\n"
    "      S.shown = LEGEND_CHUNK;\n"
    "      if (S.m) legend(S.m);\n"
    "    });\n"
    "    $(\"ak-more\").addEventListener(\"click\", function () {\n"
    "      S.shown += LEGEND_CHUNK;\n"
    "      if (S.m) legend(S.m);\n"
    "    });\n"
    "    $(\"ak-legend\").addEventListener(\"keydown\", function (e) {\n"
    "      if (e.key === \"Escape\" && S.m && S.pick !== null) pick(S.m, null);\n"
    "      if (e.key !== \"ArrowDown\" && e.key !== \"ArrowUp\") return;\n"
    "      var bs = $(\"ak-legend\").querySelectorAll(\"button.ak-key\");\n"
    "      for (var i = 0; i < bs.length; i++) {\n"
    "        if (bs[i] !== document.activeElement) continue;\n"
    "        var n = bs[i + (e.key === \"ArrowDown\" ? 1 : -1)];\n"
    "        if (n) { e.preventDefault(); n.focus(); }\n"
    "        return;\n"
    "      }\n"
    "    });\n"
    "    var cv = $(\"ak-chart\");\n"
    "    cv.addEventListener(\"mousemove\", function (e) {\n"
    "      if (!S.m) return;\n"
    "      var r = cv.getBoundingClientRect(), i = rowAt(e.clientX - r.left, e.clientY - r.top);\n"
    "      var row = i >= 0 ? S.rows[i] : null;\n"
    "      hot(S.m, row ? row.key : null);\n"
    "      H.set(\"ak-hover\", !row ? \"\" : (i + 1) + \"  \" + (row.key || \"(global)\") + \"  \" +\n"
    "        (row.cur === null ? \"-\" : S.view.presence ? row.cur + \"/\" + S.got.head.cells + \" cells present\"\n"
    "                                                  : \"latest \" + H.fmt(row.cur) + \" \" + S.m.unit));\n"
    "    });\n"
    "    cv.addEventListener(\"mouseleave\", function () { if (S.m) hot(S.m, null); H.set(\"ak-hover\", \"\"); });\n"
    "    cv.addEventListener(\"click\", function (e) {\n"
    "      if (!S.m) return;\n"
    "      var r = cv.getBoundingClientRect(), i = rowAt(e.clientX - r.left, e.clientY - r.top);\n"
    "      if (i >= 0) pick(S.m, S.pick === S.rows[i].key ? null : S.rows[i].key);\n"
    "    });\n"
    "  }";
/* The JS, verbatim: end. */

#define AK_MAX 4096
typedef struct { const char *kind; double x, y, w, h; char tok[12]; char txt[64]; int has_txt; } akm_t;
typedef struct { akm_t m[AK_MAX]; int n; } akms_t;

static void ak_push(akms_t *g, const char *kind, double x, double y, double w, double h,
                    const char *tok, const char *txt) {
    if (g->n >= AK_MAX) return;
    akm_t *m = &g->m[g->n++];
    m->kind = kind;
    m->x = x; m->y = y; m->w = w; m->h = h;
    snprintf(m->tok, sizeof(m->tok), "%s", tok);
    m->has_txt = txt != NULL;
    snprintf(m->txt, sizeof(m->txt), "%s", txt ? txt : "");
}
static int ak_count(const akms_t *g, const char *kind) {
    int n = 0;
    for (int i = 0; i < g->n; i++) if (!strcmp(g->m[i].kind, kind)) n++;
    return n;
}
static int ak_count_tok(const akms_t *g, const char *kind, const char *tok) {
    int n = 0;
    for (int i = 0; i < g->n; i++)
        if (!strcmp(g->m[i].kind, kind) && !strcmp(g->m[i].tok, tok)) n++;
    return n;
}
/* The i'th mark of a kind, by value; an empty kind when there is none,
 * so a mutation that removes it fails an assertion and not the run. */
static akm_t ak_nth(const akms_t *g, const char *kind, int nth) {
    static const akm_t none = { "", 0, 0, 0, 0, "", "", 0 };
    for (int i = 0; i < g->n; i++)
        if (!strcmp(g->m[i].kind, kind) && nth-- == 0) return g->m[i];
    return none;
}
static int near(double a, double b) { return fabs(a - b) < 1e-6; }

typedef struct { const char *key; double cur; int has; } akrank_t;

/* rank(): Array.sort with a total order is any stable sort; insertion. */
static void ak_rank(akrank_t *r, int n) {
    for (int i = 1; i < n; i++) {
        akrank_t v = r[i];
        int j = i;
        for (; j > 0; j--) {
            const akrank_t *a = &r[j - 1], *b = &v;
            int c;
            if (a->has != b->has) c = a->has ? -1 : 1;
            else if (a->has && a->cur != b->cur) c = b->cur - a->cur < 0 ? -1 : 1;
            else c = strcmp(a->key, b->key);
            if (c <= 0) break;
            r[j] = r[j - 1];
        }
        r[j] = v;
    }
}

/* total < 0 is JS's "not a number"; cut is "", "bound", "time" or
 * "stopped". */
static void ak_keys_text(int shown, long long total, const char *cut, int min, int loading,
                         char *out, size_t sz) {
    char of[48] = "";
    if (total >= 0) snprintf(of, sizeof(of), " of %lld%s", total, min ? "+" : "");
    if (loading) { snprintf(out, sz, "loading %d%s keys", shown, of); return; }
    if (!strcmp(cut, "bound")) {
        snprintf(out, sz, "%d%s keys, the first by key (the graph holds %d)", shown, of, shown);
        return;
    }
    if (!strcmp(cut, "time")) {
        snprintf(out, sz, "%d%s keys (the read was stopped at 60 s)", shown, of);
        return;
    }
    if (!strcmp(cut, "stopped")) { snprintf(out, sz, "%d%s keys (the read stopped)", shown, of); return; }
    snprintf(out, sz, "%d%s", shown, shown == 1 ? " key" : " keys");
}

static long long ak_cols_for(long long total, long long plot, long long points, long long max,
                             long long least) {
    long long n = total > max ? max : total;
    if (!(n > 0) || n * plot <= points) return plot;
    long long c = points / n;
    return c < least ? least : c;
}

/* filterRows(): the indices of the keys that hold q, ASCII case aside. */
static int ak_lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }
static int ak_filter(const char *const *keys, int n, const char *q, int *out) {
    int o = 0;
    size_t ql = strlen(q);
    for (int i = 0; i < n; i++) {
        size_t kl = strlen(keys[i]);
        int hit = ql == 0;
        for (size_t a = 0; !hit && a + ql <= kl; a++) {
            size_t b = 0;
            while (b < ql && ak_lower((unsigned char)keys[i][a + b]) == ak_lower((unsigned char)q[b])) b++;
            if (b == ql) hit = 1;
        }
        if (hit) out[o++] = i;
    }
    return o;
}

static void ak_strip_row(int n, int *row, int *ink, int *every) {
    if (n <= 512) { *row = 8; *ink = 6; *every = 5; return; }
    if (n <= 1024) { *row = 4; *ink = 2; *every = 10; return; }
    if (n <= 4096) { *row = 2; *ink = 2; *every = 50; return; }
    *row = 1; *ink = 1; *every = 100;
}

#define AK_BUCKETS 10080
static const char *ak_tier_of(long long win, int store_on, int *step, long long *w) {
    if (!store_on || win <= 86400) { *step = 10; *w = win > 86400 ? 86400 : win; return "fine"; }
    if (win <= (long long)AK_BUCKETS * 60) { *step = 60; *w = win; return "minute"; }
    *step = 3600;
    *w = win > (long long)AK_BUCKETS * 3600 ? (long long)AK_BUCKETS * 3600 : win;
    return "hour";
}

#define AK_DOTS_BELOW 5
#define AK_GAP_STEPS  2.5
#define AK_LABEL_H    10
#define AK_LABEL_GAP  11
#define AK_DIM        "--faint"
#define AK_CELLS      512

typedef struct { int k; int n; const double (*pts)[2]; const char *label; } akrow_t;
typedef struct {
    double w, h, padL, padR, padT, padB, from, to, step, t0, lo, hi, now;
    int pick, hot, labels, lines;
    const double (*band)[4];     /* the picked row's, or NULL */
    const int *has;              /* which of its cells have one */
    const char *ytop, *ybot, *xt[3];
} akopt_t;

static void ak_lines(const akrow_t *rows, int nrows, const akopt_t *opt, akms_t *m) {
    m->n = 0;
    double w = opt->w, h = opt->h;
    double x0 = opt->padL, x1 = w - opt->padR, y0 = opt->padT, y1 = h - opt->padB;
    int any = 0, i, j, n;
    for (i = 0; i < nrows; i++) if (rows[i].n) any = 1;
    if (!any) { ak_push(m, "dash", w * 0.35, h / 2, w * 0.3, 1, "--faint", NULL); return; }
    double from = opt->from, to = opt->to, lo = opt->lo, hi = opt->hi;
#define X(t) (to > from ? x0 + ((t) - from) / (to - from) * (x1 - x0) : x0)
#define Y(v) (y1 - ((v) - lo) / (hi - lo) * (y1 - y0))
    int focus = opt->hot >= 0 ? opt->hot : opt->pick;
    double gap = opt->step * AK_GAP_STEPS;
    const double (*bp)[2] = opt->band && opt->pick >= 0 && opt->pick < nrows
                            ? rows[opt->pick].pts : NULL;
    int bn = bp ? rows[opt->pick].n : 0;
    for (i = 0; bp && i < bn; i++) {
        if (!opt->has[i]) continue;
        const double *b = opt->band[i];
        double bx = X(bp[i][0]);
        double bw = fmin(fmax(1, X(bp[i][0] + opt->step) - bx), fmax(0, x1 - bx));
        if (bw > 0) ak_push(m, "band", bx, Y(b[1]), bw, Y(b[0]) - Y(b[1]), "--data", NULL);
    }
    static double rl[AK_CELLS], rh[AK_CELLS];
    static int rs[AK_CELLS];
    int rn = 0, c;
    memset(rs, 0, sizeof(rs));
    for (i = opt->lines; i < nrows; i++) {
        if (i == focus) continue;
        for (j = 0; j < rows[i].n; j++) {
            c = (int)floor((rows[i].pts[j][0] - opt->t0) / opt->step + 0.5);
            if (c < 0 || c >= AK_CELLS) continue;
            if (!rs[c] || rows[i].pts[j][1] < rl[c]) rl[c] = rows[i].pts[j][1];
            if (!rs[c] || rows[i].pts[j][1] > rh[c]) rh[c] = rows[i].pts[j][1];
            rs[c] = 1;
            if (c + 1 > rn) rn = c + 1;
        }
    }
    for (c = 0; c < rn; c++) {
        if (!rs[c]) continue;
        double ex = X(opt->t0 + c * opt->step);
        double ew = fmin(fmax(1, X(opt->t0 + (c + 1) * opt->step) - ex), fmax(0, x1 - ex));
        if (ew > 0 && ex >= x0)
            ak_push(m, "range", ex, Y(rh[c]), ew, fmax(1, Y(rl[c]) - Y(rh[c])), AK_DIM, NULL);
    }
    char tok[12];
    for (n = nrows < opt->lines ? nrows : opt->lines; n >= 0; n--) {
        i = n > 0 ? n - 1 : focus;
        if (i < 0 || (n > 0 && i == focus)) continue;
        const double (*p)[2] = rows[i].pts;
        int pn = rows[i].n;
        if (!pn) continue;
        if (focus >= 0 && i != focus) snprintf(tok, sizeof(tok), AK_DIM);
        else snprintf(tok, sizeof(tok), "--k-%d", rows[i].k);
        int dots = pn < AK_DOTS_BELOW;
        for (j = 0; j < pn; j++) {
            int left = j > 0 && p[j][0] - p[j - 1][0] <= gap;
            int right = j + 1 < pn && p[j + 1][0] - p[j][0] <= gap;
            if (j > 0 && !left)
                ak_push(m, "gap", X(p[j - 1][0]), y0, X(p[j][0]) - X(p[j - 1][0]), y1 - y0,
                        "--faint", NULL);
            if (left && !dots)
                ak_push(m, "line", X(p[j - 1][0]), Y(p[j - 1][1]), X(p[j][0]) - X(p[j - 1][0]),
                        Y(p[j][1]) - Y(p[j - 1][1]), tok, NULL);
            if ((dots || (!left && !right)) && j < pn - 1)
                ak_push(m, "dot", X(p[j][0]), Y(p[j][1]), 1.5, 1.5, tok, NULL);
        }
        ak_push(m, "last", X(p[pn - 1][0]), Y(p[pn - 1][1]), 2.5, 2.5, tok, NULL);
    }
    int li[64], ln = 0, lc = 0;
    double ly[64];
    for (i = 0; i < nrows && opt->padR > 8 && ln < 63; i++) {
        if (!rows[i].n) continue;
        if (lc >= opt->labels && i != focus) continue;
        lc++;
        double y = Y(rows[i].pts[rows[i].n - 1][1]);
        for (j = ln; j > 0 && ly[j - 1] > y; j--) { li[j] = li[j - 1]; ly[j] = ly[j - 1]; }
        li[j] = i;
        ly[j] = y;
        ln++;
    }
    for (j = 1; j < ln; j++) if (ly[j] < ly[j - 1] + AK_LABEL_GAP) ly[j] = ly[j - 1] + AK_LABEL_GAP;
    double over = ln ? ly[ln - 1] - (y1 - AK_LABEL_H / 2.0) : 0;
    for (j = 0; j < ln; j++) {
        if (focus >= 0 && li[j] != focus) snprintf(tok, sizeof(tok), AK_DIM);
        else snprintf(tok, sizeof(tok), "--k-%d", rows[li[j]].k);
        ak_push(m, "label", x1 + 6, over > 0 ? ly[j] - over : ly[j], opt->padR - 8, AK_LABEL_H,
                tok, rows[li[j]].label);
    }
#undef X
#undef Y
}

static void ak_frame(const akopt_t *opt, akms_t *m) {
    m->n = 0;
    double w = opt->w, h = opt->h;
    double x0 = opt->padL, x1 = w - opt->padR, y0 = opt->padT, y1 = h - opt->padB;
    ak_push(m, "axis", x0, y0, x1 - x0, 1, "--rule", NULL);
    ak_push(m, "axis", x0, y1, x1 - x0, 1, "--rule", NULL);
    ak_push(m, "num", 2, y0 + 5, x0 - 6, 10, "--muted", opt->ytop);
    ak_push(m, "num", 2, y1 - 5, x0 - 6, 10, "--muted", opt->ybot);
    ak_push(m, "num", x0, h - 6, 96, 10, "--muted", opt->xt[0]);
    ak_push(m, "num", (x0 + x1) / 2 - 24, h - 6, 96, 10, "--muted", opt->xt[1]);
    ak_push(m, "num", x1 - 48, h - 6, 96, 10, "--muted", opt->xt[2]);
    if (opt->to > opt->from && opt->now >= opt->from && opt->now <= opt->to)
        ak_push(m, "now", x0 + (opt->now - opt->from) / (opt->to - opt->from) * (x1 - x0), y0, 1,
                y1 - y0, "--signal", NULL);
}

typedef struct { int k; int n; const int *cells; } akstrip_t;
typedef struct { double w, rowH, ink; int every; double padL, padR; int ncell, pick, hot; const char *xt[3]; } aksopt_t;

static void ak_strips(const akstrip_t *rows, int nrows, const aksopt_t *opt, akms_t *m) {
    m->n = 0;
    double x0 = opt->padL, pw = opt->w - opt->padL - opt->padR, rh = opt->rowH;
    int any = 0, i, j;
    for (i = 0; i < nrows; i++) if (rows[i].n) any = 1;
    if (!any) {
        ak_push(m, "dash", opt->w * 0.35, (nrows > 1 ? nrows : 1) * rh / 2, opt->w * 0.3, 1,
                "--faint", NULL);
        return;
    }
    int focus = opt->hot >= 0 ? opt->hot : opt->pick;
    char tok[12], num[16];
    for (i = 0; i < nrows; i++) {
        const int *c = rows[i].cells;
        double y = i * rh;
        if (focus >= 0 && i != focus) snprintf(tok, sizeof(tok), AK_DIM);
        else snprintf(tok, sizeof(tok), "--k-%d", rows[i].k);
        if (i == 0 || (i + 1) % opt->every == 0) {
            snprintf(num, sizeof(num), "%d", i + 1);
            ak_push(m, "num", 2, y + rh / 2, x0 - 4, 8, "--muted", num);
        }
        for (j = 0; j < rows[i].n; j++) {
            int a = c[j], e = a;
            while (j + 1 < rows[i].n && c[j + 1] == e + 1) { j++; e++; }
            ak_push(m, "cell", x0 + (double)a / opt->ncell * pw, y,
                    fmax(1, (double)(e + 1 - a) / opt->ncell * pw), opt->ink, tok, NULL);
        }
    }
    double ty = nrows * rh + 8;
    ak_push(m, "num", x0, ty, 96, 10, "--muted", opt->xt[0]);
    ak_push(m, "num", x0 + pw / 2 - 24, ty, 96, 10, "--muted", opt->xt[1]);
    ak_push(m, "num", x0 + pw - 48, ty, 96, 10, "--muted", opt->xt[2]);
}

/* ── the ported half, tested ────────────────────────────────────── */

static void test_the_page_carries_the_ported_js(void) {
    const char *p = page();
    WT_HAS(p, JS_RANK);
    WT_HAS(p, JS_KEYSTEXT);
    WT_HAS(p, JS_TIEROF);
    WT_HAS(p, JS_LINES);
    WT_HAS(p, JS_FRAME);
    WT_HAS(p, JS_STRIPS);
    WT_HAS(p, JS_COLSFOR);
    WT_HAS(p, JS_FILTERROWS);
    WT_HAS(p, JS_STRIPROW);
    /* The constants the port copies. */
    WT_HAS(p, "  var DOTS_BELOW = 5;\n  var GAP_STEPS = 2.5;\n");
    WT_HAS(p, "  var LABELS = 5;\n  var LABEL_H = 10;\n  var LABEL_GAP = 11;\n");
    WT_HAS(p, "  var PAD_L = 48, PAD_R = 132, PAD_T = 6, PAD_B = 16;\n");
    WT_HAS(p, "  var DIM = \"--faint\";\n");
    WT_HAS(p, "  var LINES = 256;\n");
    WT_HAS(p, "  var KEYS_MAX = 8192;\n");
    WT_HAS(p, "  var POINTS = 524288;\n");
    WT_HAS(p, "  var POINTS_STRIPS = 131072;\n");
    WT_HAS(p, "  var READ_MS = 60000;\n");
    WT_HAS(p, "  var DRAW_MS = 300;\n");
    WT_HAS(p, "  var LEGEND_CHUNK = 200;\n");
    /* The graph holds as many keys as a rollup can. */
    WT_EQ(WEB_MAX_KEYS_MAX, 8192);
    /* The route's bounds, as the page copies them. */
    WT_HAS(p, "  var COLS_MIN = 8, COLS_MAX = 480, BUCKETS = 10080;\n");
    WT_EQ(WEB_ALLKEYS_COLS_MIN, 8);
    WT_EQ(WEB_ALLKEYS_COLS_MAX, 480);
    WT_EQ(WEB_ALLKEYS_BUCKETS, AK_BUCKETS);
    WT_HAS(p, "  function gnum(v) { return typeof v === \"number\" && isFinite(v); }\n");
}

/* The legend's order: latest value largest first, a key with nothing
 * after every key with something, equal values by the key's bytes. */
static void test_legend_order(void) {
    akrank_t r[6] = {
        { "wlan0mon", 29.4, 1 }, { "eth0", 312.8, 1 }, { "lo", 0, 0 },
        { "br0", 29.4, 1 }, { "docker0", 0, 1 }, { "aa0", 0, 0 },
    };
    ak_rank(r, 6);
    WT_ASSERT(!strcmp(r[0].key, "eth0"));
    WT_ASSERT(!strcmp(r[1].key, "br0"));          /* 29.4 twice: by key */
    WT_ASSERT(!strcmp(r[2].key, "wlan0mon"));
    WT_ASSERT(!strcmp(r[3].key, "docker0"));      /* a real 0 is a value */
    WT_ASSERT(!strcmp(r[4].key, "aa0"));          /* nothing: last, by key */
    WT_ASSERT(!strcmp(r[5].key, "lo"));
    /* Negative values (RSSI) still sort largest first. */
    akrank_t s[3] = { { "a", -70, 1 }, { "b", -40, 1 }, { "c", -90, 1 } };
    ak_rank(s, 3);
    WT_ASSERT(!strcmp(s[0].key, "b") && !strcmp(s[1].key, "a") && !strcmp(s[2].key, "c"));
}

/* "N of M keys": all of them said plainly, a cap said with its rule. */
static void test_n_of_m_caption(void) {
    char b[120];
    /* A whole read: the count, plainly, however many. */
    ak_keys_text(1, 1, "", 0, 0, b, sizeof(b));
    WT_ASSERT(!strcmp(b, "1 key"));
    ak_keys_text(300, 300, "", 0, 0, b, sizeof(b));
    WT_ASSERT(!strcmp(b, "300 keys"));
    ak_keys_text(0, 0, "", 0, 0, b, sizeof(b));
    WT_ASSERT(!strcmp(b, "0 keys"));
    /* A read under way: "loading N of M keys". */
    ak_keys_text(640, 8192, "", 0, 1, b, sizeof(b));
    WT_ASSERT(!strcmp(b, "loading 640 of 8192 keys"));
    ak_keys_text(0, -1, "", 0, 1, b, sizeof(b));
    WT_ASSERT(!strcmp(b, "loading 0 keys"));
    /* What bounds it, said: the graph's 8,192, the 60 s, a read the
     * server ended; a total the server stopped counting at is "+". */
    ak_keys_text(8192, 9000, "bound", 0, 0, b, sizeof(b));
    WT_ASSERT(!strcmp(b, "8192 of 9000 keys, the first by key (the graph holds 8192)"));
    ak_keys_text(8192, 65536, "bound", 1, 0, b, sizeof(b));
    WT_ASSERT(!strcmp(b, "8192 of 65536+ keys, the first by key (the graph holds 8192)"));
    ak_keys_text(3072, 8192, "time", 0, 0, b, sizeof(b));
    WT_ASSERT(!strcmp(b, "3072 of 8192 keys (the read was stopped at 60 s)"));
    ak_keys_text(448, 512, "stopped", 0, 0, b, sizeof(b));
    WT_ASSERT(!strcmp(b, "448 of 512 keys (the read stopped)"));
    /* The caption is built from it: the total the route's first answer
     * gave, and loading while a first read runs. */
    WT_HAS(page(), "    var keys = keysText(S.rows.length, g.total, g.cut, g.min, S.loading && !S.done);\n");
    WT_HAS(page(), "      source: m.name + \", \" + keys + \", \" + head.source,\n");
    WT_HAS(page(), "      H.set(\"a-src\", m.name + \", \" + keysText(0, null, \"\", false, true));\n");
    /* A picked key the key picker's 256 do not hold is said. */
    WT_HAS(page(), "      (S.pickOut && S.pick !== null ? \"; \" + S.pick + \" is not one of the key picker's 256\" : \"\") +\n");
}

/* The cells a key is read in: the plot's while every key's together
 * are within what the graph holds, else what that leaves each, never
 * under the route's least. */
static void test_cols_for(void) {
    WT_EQ(ak_cols_for(19, 480, 524288, 8192, 8), 480);
    WT_EQ(ak_cols_for(1092, 480, 524288, 8192, 8), 480);
    WT_EQ(ak_cols_for(1093, 480, 524288, 8192, 8), 479);
    WT_EQ(ak_cols_for(4096, 480, 524288, 8192, 8), 128);
    WT_EQ(ak_cols_for(8192, 480, 524288, 8192, 8), 64);
    WT_EQ(ak_cols_for(100000, 480, 524288, 8192, 8), 64);     /* the graph holds 8,192 */
    WT_EQ(ak_cols_for(8192, 480, 131072, 8192, 8), 16);       /* a presence metric */
    WT_EQ(ak_cols_for(8192, 480, 32768, 8192, 8), 8);         /* never under the least */
    WT_EQ(ak_cols_for(0, 480, 524288, 8192, 8), 480);
    WT_EQ(ak_cols_for(8192, 60, 524288, 8192, 8), 60);        /* a narrow plot is not widened */
    /* Whatever it answers is a cols the route takes. */
    WT_ASSERT(ak_cols_for(8192, 480, 32768, 8192, 8) >= WEB_ALLKEYS_COLS_MIN);
    /* 8,192 keys at their cells are within the bound. */
    WT_ASSERT(8192 * ak_cols_for(8192, 480, 524288, 8192, 8) <= 524288);
}

/* The legend's filter: by the key's text, ASCII case aside; the
 * indices, so an entry keeps its rank among every key. */
static void test_legend_filter(void) {
    static const char *const K[5] = { "02:de:00:00:00:10", "0A:DE:00:00:02:05", "eth0",
                                      "192.0.2.10", "" };
    int out[5];
    WT_EQ(ak_filter(K, 5, "", out), 5);
    WT_EQ(ak_filter(K, 5, "de:00", out), 2);
    WT_ASSERT(out[0] == 0 && out[1] == 1);          /* a kept rank, not a new one */
    WT_EQ(ak_filter(K, 5, "0a:de", out), 1);
    WT_EQ(out[0], 1);
    WT_EQ(ak_filter(K, 5, "ETH", out), 1);
    WT_EQ(out[0], 2);
    WT_EQ(ak_filter(K, 5, "2.10", out), 1);
    WT_EQ(ak_filter(K, 5, "zz", out), 0);
    WT_EQ(ak_filter(K, 5, "02:de:00:00:00:100", out), 0);
}

/* A presence row's height by how many rows: 8,192 are a canvas of
 * 8,192 px, inside what a browser makes. */
static void test_strip_rows(void) {
    static const struct { int n, row, ink, every; } C[] = {
        { 1, 8, 6, 5 }, { 512, 8, 6, 5 }, { 513, 4, 2, 10 }, { 1024, 4, 2, 10 },
        { 1025, 2, 2, 50 }, { 4096, 2, 2, 50 }, { 4097, 1, 1, 100 }, { 8192, 1, 1, 100 },
    };
    for (size_t i = 0; i < sizeof(C) / sizeof(C[0]); i++) {
        int row, ink, every;
        ak_strip_row(C[i].n, &row, &ink, &every);
        WT_EQ(row, C[i].row);
        WT_EQ(ink, C[i].ink);
        WT_EQ(every, C[i].every);
        WT_ASSERT(C[i].n * row <= 8192);
    }
}

/* The tier a window is read in keeps a key within the route's rows. */
static void test_tier_of(void) {
    int step;
    long long w;
    static const struct { long long win; int store; const char *tier; int step; long long w; } C[] = {
        { 3600, 1, "fine", 10, 3600 }, { 21600, 1, "fine", 10, 21600 },
        { 86400, 1, "fine", 10, 86400 }, { 604800, 1, "minute", 60, 604800 },
        { 2592000, 1, "hour", 3600, 2592000 }, { 34560000, 1, "hour", 3600, 34560000 },
        { 604800, 0, "fine", 10, 86400 }, { 3600, 0, "fine", 10, 3600 },
    };
    for (size_t i = 0; i < sizeof(C) / sizeof(C[0]); i++) {
        const char *t = ak_tier_of(C[i].win, C[i].store, &step, &w);
        WT_ASSERT(!strcmp(t, C[i].tier));
        WT_EQ(step, C[i].step);
        WT_EQ(w, C[i].w);
        /* Every window the page offers is inside the route's bound. */
        WT_ASSERT(w / step <= WEB_ALLKEYS_BUCKETS);
    }
}

/* Stable colour: a key's colour is the TUI's hash of it (src/ip_color.c
 * through the page's ipColorIndex, which test_tui_colors.c holds to the
 * C), the same on every load and in every view, because nothing but
 * the key's bytes goes in. The values are pinned. */
static void test_colour_is_the_keys_hash(void) {
    static const struct { const char *key; int k; } C[] = {
        { "eth0", 6 }, { "wlan0mon", 1 }, { "lo", 0 }, { "10.0.0.1", 1 },
        { "02:de:00:00:00:10", 3 }, { "aa:bb:cc:dd:ee:ff", 1 }, { "6", 3 }, { "36", 6 },
        { "", 0 },
    };
    for (size_t i = 0; i < sizeof(C) / sizeof(C[0]); i++) WT_EQ(ip_color_index(C[i].key), C[i].k);
    WT_EQ(IP_NUM_COLORS, 8);
    const char *p = page();
    /* The page's one helper, lent; the row's index; the swatch's token;
     * the mark's token. Nothing else names a colour. */
    WT_HAS(p, "    keySpan: keySpan, colorIndex: ipColorIndex, baseline: baseline,");
    WT_HAS(p, "    return { key: k.key, k: H.colorIndex(k.key), pts: pts, cells: cells, band: null,\n");
    WT_HAS(p, "      sw.style.background = \"var(--k-\" + r.k + \")\";\n");
    WT_HAS(p, "      var tok = focus >= 0 && i !== focus ? DIM : \"--k-\" + rows[i].k;\n");
    /* The same helper the device drawer's swatch and the Devices
     * table's take their colour from. */
    WT_HAS(p, "    return theme().k[ipColorIndex(k)];\n");
    WT_HAS(p, "    $(\"dr-sw\").style.background = keyColor(mac);\n");
}

static akopt_t lopt(void) {
    akopt_t o;
    memset(&o, 0, sizeof(o));
    o.w = 400; o.h = 200; o.padL = 40; o.padR = 100;
    o.from = 0; o.to = 100; o.step = 10; o.lo = 0; o.hi = 10;
    o.pick = -1; o.hot = -1; o.labels = 5; o.lines = 256;
    return o;
}

static const double PA[6][2] = { {0,10}, {10,8}, {20,6}, {30,4}, {40,2}, {100,5} };
static const double PB[2][2] = { {0,1}, {10,1} };

static akms_t G;

static void test_lines_states(void) {
    akopt_t o = lopt();
    /* R5: nothing to draw is the dash, alone. */
    akrow_t none[2] = { { 3, 0, NULL, "1 a" }, { 5, 0, NULL, "2 b" } };
    ak_lines(none, 2, &o, &G);
    WT_EQ(G.n, 1);
    WT_ASSERT(!strcmp(G.m[0].kind, "dash") && !strcmp(G.m[0].tok, "--faint"));
    ak_lines(none, 0, &o, &G);
    WT_EQ(G.n, 1);

    akrow_t rows[3] = { { 3, 6, PA, "1 a" }, { 5, 2, PB, "2 b" }, { 1, 0, NULL, "3 c" } };
    ak_lines(rows, 3, &o, &G);
    /* Each key in its own colour token, the last legend row drawn first
     * so the largest is on top. */
    WT_ASSERT(!strcmp(G.m[0].tok, "--k-5"));
    WT_EQ(ak_count_tok(&G, "line", "--k-3"), 4);
    WT_EQ(ak_count_tok(&G, "line", "--k-5"), 0);
    /* R6: two points are dots, never a line; the last is its own mark. */
    WT_EQ(ak_count_tok(&G, "dot", "--k-5"), 1);
    WT_EQ(ak_count_tok(&G, "last", "--k-5"), 1);
    WT_EQ(ak_count_tok(&G, "last", "--k-3"), 1);
    /* R5: the 60 s hole in row a is a gap mark and no line crosses it. */
    WT_EQ(ak_count(&G, "gap"), 1);
    akm_t gp = ak_nth(&G, "gap", 0);
    WT_ASSERT(near(gp.x, 144) && near(gp.w, 156));
    for (int i = 0; i < G.n; i++)
        if (!strcmp(G.m[i].kind, "line")) WT_ASSERT(G.m[i].x + G.m[i].w <= 144 + 1e-6);
    /* One shared scale: a value is one height in every row. Row a's
     * first point (10, the scale's top) is the plot's top; row b's 1 is
     * a tenth up. */
    akm_t l0 = ak_nth(&G, "line", 0);
    WT_ASSERT(near(l0.x, 40) && near(l0.y, 0) && near(l0.w, 26) && near(l0.h, 40));
    akm_t d0 = ak_nth(&G, "dot", 0);
    WT_ASSERT(near(d0.x, 40) && near(d0.y, 180));
    /* A row with no point has no label: two rows are labelled, not
     * three. (That it has no mark at all cannot be shown by a mutation
     * of the port: without its `!pn` skip the port reads a NULL row.) */
    WT_EQ(ak_count(&G, "label"), 2);
    /* The only tokens are key colours and grey: no accent, no heat. */
    for (int i = 0; i < G.n; i++)
        WT_ASSERT(!strncmp(G.m[i].tok, "--k-", 4) || !strcmp(G.m[i].tok, "--faint"));
}

/* An isolated point between two gaps is a dot, or it would be invisible. */
static void test_lines_isolated_point(void) {
    static const double P[7][2] = { {0,1}, {10,2}, {50,9}, {90,3}, {100,4}, {110,5}, {120,6} };
    akrow_t rows[1] = { { 2, 7, P, "1 x" } };
    akopt_t o = lopt();
    o.to = 120;
    ak_lines(rows, 1, &o, &G);
    WT_EQ(ak_count(&G, "gap"), 2);
    WT_EQ(ak_count(&G, "dot"), 1);
    akm_t d = ak_nth(&G, "dot", 0);
    WT_ASSERT(near(d.x, 40 + 50.0 / 120 * 260));
    WT_EQ(ak_count(&G, "line"), 4);
}

/* A focus (the hovered row, else the picked) is drawn last in its
 * colour; every other row goes to --rule, its label too. */
static void test_lines_focus(void) {
    akrow_t rows[2] = { { 3, 6, PA, "1 a" }, { 5, 2, PB, "2 b" } };
    akopt_t o = lopt();
    o.pick = 1;
    ak_lines(rows, 2, &o, &G);
    WT_EQ(ak_count_tok(&G, "line", "--faint"), 4);
    WT_EQ(ak_count_tok(&G, "line", "--k-3"), 0);
    WT_EQ(ak_count_tok(&G, "last", "--k-5"), 1);
    /* Row b's marks come after row a's: forward. */
    int last_a = -1, first_b = -1;
    for (int i = 0; i < G.n; i++) {
        if (!strcmp(G.m[i].kind, "label")) break;
        if (!strcmp(G.m[i].tok, "--faint")) last_a = i;
        if (!strcmp(G.m[i].tok, "--k-5") && first_b < 0) first_b = i;
    }
    WT_ASSERT(last_a >= 0 && first_b > last_a);
    WT_EQ(ak_count_tok(&G, "label", "--faint"), 1);
    WT_EQ(ak_count_tok(&G, "label", "--k-5"), 1);
    /* The hover wins over the pick. */
    o.hot = 0;
    ak_lines(rows, 2, &o, &G);
    WT_EQ(ak_count_tok(&G, "line", "--k-3"), 4);
    WT_EQ(ak_count_tok(&G, "last", "--faint"), 1);
    /* No focus: every row in its colour. */
    o.pick = -1; o.hot = -1;
    ak_lines(rows, 2, &o, &G);
    WT_EQ(ak_count_tok(&G, "line", "--faint"), 0);
    /* The dim token is --faint, a step above --rule (owner ruling
     * 2026-11-11): 2.84:1 on --bg where --rule is 1.65:1. Never --rule. */
    o.pick = 1;
    ak_lines(rows, 2, &o, &G);
    WT_EQ(ak_count_tok(&G, "line", "--rule"), 0);
    WT_EQ(ak_count_tok(&G, "last", "--rule"), 0);
    WT_EQ(ak_count_tok(&G, "label", "--rule"), 0);
}

/* The band is the picked key's, under every line, and only then. */
static void test_lines_band(void) {
    akrow_t rows[2] = { { 3, 6, PA, "1 a" }, { 5, 2, PB, "2 b" } };
    static const double B[6][4] = { {1,9,5,2}, {1,9,5,2}, {0,0,0,0}, {1,9,5,2}, {1,9,5,2}, {1,9,5,2} };
    static const int HAS[6] = { 1, 1, 0, 1, 1, 1 };
    akopt_t o = lopt();
    o.band = B; o.has = HAS;
    ak_lines(rows, 2, &o, &G);
    WT_EQ(ak_count(&G, "band"), 0);          /* a band given, no key picked */
    o.pick = 0;
    ak_lines(rows, 2, &o, &G);
    /* Six points: the warming cell has none, and the last sits on the
     * plot's right edge, where a band has no width left. */
    WT_EQ(ak_count(&G, "band"), 4);
    WT_ASSERT(!strcmp(G.m[0].kind, "band") && !strcmp(G.m[0].tok, "--data"));
    akm_t b0 = ak_nth(&G, "band", 0);
    WT_ASSERT(near(b0.x, 40) && near(b0.w, 26) && near(b0.y, 20) && near(b0.h, 160));
    /* The hover does not move the band: it stays the picked key's. */
    o.hot = 1;
    ak_lines(rows, 2, &o, &G);
    WT_EQ(ak_count(&G, "band"), 4);
}

/* Past opt.lines rows a key is not a line: the rest are one range a
 * cell, their least to their most, under every line; the focus row is
 * a line whatever its rank. Three rows, lines for the first one. */
static void test_lines_fold_into_a_range(void) {
    static const double P0[5][2] = { {0,9}, {10,9}, {20,9}, {30,9}, {40,9} };
    static const double P1[5][2] = { {0,2}, {10,4}, {20,2}, {30,4}, {40,2} };
    static const double P2[3][2] = { {0,6}, {10,1}, {40,5} };
    akrow_t rows[3] = { { 1, 5, P0, "1 a" }, { 2, 5, P1, "2 b" }, { 3, 3, P2, "3 c" } };
    akopt_t o = lopt();
    o.to = 40;
    /* Every row a line: no range. */
    ak_lines(rows, 3, &o, &G);
    WT_EQ(ak_count(&G, "range"), 0);
    WT_EQ(ak_count(&G, "last"), 3);
    o.lines = 1;
    ak_lines(rows, 3, &o, &G);
    /* Rows b and c hold cells 0, 1, 2, 3, 4; the last is on the plot's
     * right edge and has no width left. */
    WT_EQ(ak_count(&G, "range"), 4);
    WT_ASSERT(!strcmp(G.m[0].kind, "range") && !strcmp(G.m[0].tok, "--faint"));
    akm_t r0 = ak_nth(&G, "range", 0), r1 = ak_nth(&G, "range", 1), r2 = ak_nth(&G, "range", 2);
    /* Cell 0: 2 to 6 on a 0..10 scale of 200 px. */
    WT_ASSERT(near(r0.x, 40) && near(r0.w, 65) && near(r0.y, 80) && near(r0.h, 80));
    /* Cell 1: 1 to 4. */
    WT_ASSERT(near(r1.y, 120) && near(r1.h, 60));
    /* Cell 2: row b alone, 2 to 2: a range of one value is still seen. */
    WT_ASSERT(near(r2.y, 160) && near(r2.h, 1));
    /* Only row a is a line; b and c have no line, no dot, no last. */
    WT_EQ(ak_count(&G, "last"), 1);
    WT_EQ(ak_count_tok(&G, "line", "--k-1"), 4);
    WT_EQ(ak_count_tok(&G, "line", "--k-2"), 0);
    WT_EQ(ak_count_tok(&G, "dot", "--k-3"), 0);
    /* A folded row that is the focus is a line, in its colour, and is
     * out of the range: row c picked leaves row b's 2..4 alone. */
    o.pick = 2;
    ak_lines(rows, 3, &o, &G);
    WT_EQ(ak_count_tok(&G, "last", "--k-3"), 1);
    WT_EQ(ak_count_tok(&G, "dot", "--k-3"), 2);
    WT_EQ(ak_count_tok(&G, "line", "--faint"), 4);
    r0 = ak_nth(&G, "range", 0);
    WT_ASSERT(near(r0.y, 160) && near(r0.h, 1));
    /* The cells are counted from t0, not from a shrunk window's start. */
    o.pick = -1; o.from = 10; o.t0 = 0;
    ak_lines(rows, 3, &o, &G);
    WT_EQ(ak_count(&G, "range"), 3);                 /* cell 0 is left of the plot */
    WT_ASSERT(near(ak_nth(&G, "range", 0).x, 40));
}

/* End labels: the first LABELS rows with a point, and the focus row
 * whatever its rank; never two closer than LABEL_GAP; each carries its
 * rank and key, which is what tells eight colours' lines apart. */
static void test_lines_labels(void) {
    static double P[8][5][2];
    static char L[8][16];
    akrow_t rows[8];
    for (int r = 0; r < 8; r++) {
        for (int j = 0; j < 5; j++) { P[r][j][0] = j * 10; P[r][j][1] = 5 + r * 0.01; }
        snprintf(L[r], sizeof(L[r]), "%d key%d", r + 1, r);
        rows[r].k = r; rows[r].n = 5; rows[r].pts = (const double (*)[2])P[r]; rows[r].label = L[r];
    }
    akopt_t o = lopt();
    o.to = 40;
    ak_lines(rows, 8, &o, &G);
    WT_EQ(ak_count(&G, "label"), 5);
    double prev = -1e9;
    for (int i = 0; i < 5; i++) {
        akm_t l = ak_nth(&G, "label", i);
        WT_ASSERT(l.has_txt);
        WT_ASSERT(l.y >= prev + AK_LABEL_GAP - 1e-6);
        WT_ASSERT(near(l.x, 306) && near(l.w, 92) && near(l.h, 10));
        prev = l.y;
    }
    /* All five values are within a pixel: the labels are stacked, top
     * down in value order (the largest value is the highest label). */
    WT_ASSERT(!strcmp(ak_nth(&G, "label", 0).txt, "5 key4"));
    WT_ASSERT(!strcmp(ak_nth(&G, "label", 4).txt, "1 key0"));
    /* The focus row is labelled though it is the eighth. */
    o.hot = 7;
    ak_lines(rows, 8, &o, &G);
    WT_EQ(ak_count(&G, "label"), 6);
    WT_EQ(ak_count_tok(&G, "label", "--k-7"), 1);
    WT_EQ(ak_count_tok(&G, "label", "--faint"), 5);
    /* A stack that would leave the plot is lifted back inside it. */
    for (int r = 0; r < 8; r++) for (int j = 0; j < 5; j++) P[r][j][1] = 0;
    o.hot = -1;
    ak_lines(rows, 8, &o, &G);
    WT_ASSERT(near(ak_nth(&G, "label", 4).y, 195));
    WT_ASSERT(near(ak_nth(&G, "label", 0).y, 195 - 4 * AK_LABEL_GAP));
    /* No room for labels: none. */
    o.padR = 4;
    ak_lines(rows, 8, &o, &G);
    WT_EQ(ak_count(&G, "label"), 0);
}

/* R10: with every colour gone the rows are still told apart, by the
 * label's words and by the order they are drawn in. */
static void test_lines_read_in_greyscale(void) {
    akrow_t rows[2] = { { 3, 6, PA, "1 a" }, { 3, 2, PB, "2 b" } };
    akopt_t o = lopt();
    ak_lines(rows, 2, &o, &G);
    /* Two keys that hash to one colour: the labels still differ. */
    akm_t a = ak_nth(&G, "label", 0), b = ak_nth(&G, "label", 1);
    WT_ASSERT(a.has_txt && b.has_txt && strcmp(a.txt, b.txt) != 0);
    WT_ASSERT(!strcmp(a.tok, b.tok));
    /* The last value is its own kind of mark, one a row. */
    WT_EQ(ak_count(&G, "last"), 2);
}

static void test_frame(void) {
    akopt_t o = lopt();
    o.padT = 6; o.padB = 16; o.now = 100;
    o.ytop = "10"; o.ybot = "0"; o.xt[0] = "10:00"; o.xt[1] = "10:30"; o.xt[2] = "11:00";
    ak_frame(&o, &G);
    WT_EQ(ak_count(&G, "axis"), 2);
    WT_EQ(ak_count(&G, "num"), 5);            /* R4: three times, and the scale's two ends */
    WT_ASSERT(!strcmp(ak_nth(&G, "num", 0).txt, "10"));
    WT_ASSERT(!strcmp(ak_nth(&G, "num", 1).txt, "0"));
    WT_ASSERT(!strcmp(ak_nth(&G, "num", 2).txt, "10:00"));
    WT_ASSERT(!strcmp(ak_nth(&G, "num", 4).txt, "11:00"));
    WT_EQ(ak_count(&G, "now"), 1);
    akm_t nw = ak_nth(&G, "now", 0);
    WT_ASSERT(near(nw.x, 300) && near(nw.y, 6) && near(nw.h, 178) && !strcmp(nw.tok, "--signal"));
    /* The one accent: nothing else in the frame is --signal. */
    for (int i = 0; i < G.n; i++)
        if (strcmp(G.m[i].kind, "now")) WT_ASSERT(strcmp(G.m[i].tok, "--signal") != 0);
    /* Now outside the window (a shrunk one): no mark. */
    o.now = 101;
    ak_frame(&o, &G);
    WT_EQ(ak_count(&G, "now"), 0);
    o.now = -1;
    ak_frame(&o, &G);
    WT_EQ(ak_count(&G, "now"), 0);
}

/* Presence: stacked strips, one row a key in the legend's order, a run
 * of present cells one mark in the key's colour. */
static void test_strips(void) {
    static const int C0[4] = { 0, 1, 2, 5 }, C2[1] = { 9 };
    akstrip_t rows[6] = { { 2, 4, C0 }, { 4, 0, NULL }, { 7, 1, C2 }, { 0, 0, NULL },
                          { 1, 0, NULL }, { 6, 0, NULL } };
    aksopt_t o = { 128, 8, 6, 5, 28, 0, 10, -1, -1, { "10:00", "10:30", "11:00" } };
    ak_strips(rows, 6, &o, &G);
    WT_EQ(ak_count(&G, "cell"), 3);
    akm_t c0 = ak_nth(&G, "cell", 0), c1 = ak_nth(&G, "cell", 1), c2 = ak_nth(&G, "cell", 2);
    WT_ASSERT(near(c0.x, 28) && near(c0.w, 30) && near(c0.y, 0) && near(c0.h, 6));
    WT_ASSERT(near(c1.x, 78) && near(c1.w, 10));
    WT_ASSERT(!strcmp(c0.tok, "--k-2") && !strcmp(c2.tok, "--k-7"));
    WT_ASSERT(near(c2.y, 16) && near(c2.x, 118));
    /* A row of 8 px draws 6 of them. The rank is 8 px of text whatever
     * the row's height. */
    WT_ASSERT(near(ak_nth(&G, "num", 0).h, 8));
    /* The rank on the first row and every fifth, 1 and 5; then the
     * window's three times under the last row. */
    WT_EQ(ak_count(&G, "num"), 5);
    WT_ASSERT(!strcmp(ak_nth(&G, "num", 2).txt, "10:00") && near(ak_nth(&G, "num", 2).y, 56));
    WT_ASSERT(!strcmp(ak_nth(&G, "num", 4).txt, "11:00") && near(ak_nth(&G, "num", 4).x, 80));
    WT_ASSERT(!strcmp(ak_nth(&G, "num", 0).txt, "1"));
    WT_ASSERT(!strcmp(ak_nth(&G, "num", 1).txt, "5"));
    WT_ASSERT(near(ak_nth(&G, "num", 1).y, 36));
    /* A focus dims the others. */
    o.hot = 2;
    ak_strips(rows, 6, &o, &G);
    WT_EQ(ak_count_tok(&G, "cell", "--faint"), 2);
    WT_EQ(ak_count_tok(&G, "cell", "--k-7"), 1);
    /* R5: no key present at all is the dash. */
    akstrip_t none[2] = { { 2, 0, NULL }, { 4, 0, NULL } };
    ak_strips(none, 2, &o, &G);
    WT_EQ(G.n, 1);
    WT_ASSERT(!strcmp(G.m[0].kind, "dash"));
}

/* ── the page's other half, pinned by whole functions ───────────── */

static void test_wiring(void) {
    const char *p = page();
    /* The module after facts.js and before app.js; its CSS last. */
    const char *fj = strstr(p, "// slothweb: G1 on every network fact");
    const char *aj = strstr(p, "// slothweb: every key of a metric on the Activity page's one graph");
    const char *mj = strstr(p, "window.SlothAllKeys = { init: init, main: main,");
    const char *hook = strstr(p, "    if (window.SlothAllKeys && SlothAllKeys.main(m)) return;\n");
    WT_ASSERT(fj && aj && mj && hook && fj < aj && aj < mj && mj < hook);
    /* The one hook in mainChart(), before anything of the one-key
     * graph is read. */
    WT_HAS(p, "  function mainChart() {\n"
              "    var m = selMetric();\n"
              "    // \"keys: all\" (web/ui/allkeys.js) draws the graph itself.\n"
              "    if (window.SlothAllKeys && SlothAllKeys.main(m)) return;\n"
              "    if (!m || !A.keys.length) { set(\"a-title\", m ? m.name : \"-\"); return; }\n");
    /* The helpers lent, once. */
    WT_HAS(p, "  if (window.SlothAllKeys) SlothAllKeys.init({ el: el, set: set, getJSON: getJSON, tok: tok, fmt: fmt,\n"
              "    keySpan: keySpan, colorIndex: ipColorIndex, baseline: baseline, bands: bands, hhmmss: hhmmss,\n"
              "    prefGet: prefGet, prefSet: prefSet, openDrawer: openDrawer,\n"
              "    isMac: function (k) { return MAC_RE.test(k); }, sens: function () { return sens; },\n"
              "    scope: function () { return SCOPE; }, scopeWord: function (s) { return SCOPE_WORD[s]; },\n"
              "    storeOn: function () { return A.storeOn; }, key: function () { return A.keys[A.key] || \"\"; },\n"
              "    pickKey: function (k) {\n"
              "      var i = A.keys.indexOf(k);\n"
              "      if (i >= 0) { A.key = i; $(\"a-key\").value = String(i); actKeep(); }\n"
              "      return i >= 0;\n"
              "    },\n"
              "    active: function () { return view === \"activity\"; },\n"
              "    redraw: function () { if (view === \"activity\") refresh(); } });\n");
    /* The control, in the page's existing button style, and its box. */
    WT_HAS(p, "<button type=\"button\" class=\"dt-reset\" id=\"ak-mode\" aria-pressed=\"false\" title=\"one: the picked key over its baseline band; all: every key of the metric on this graph, one colour a key, on one shared scale, with a legend\">keys: one</button>");
    WT_HAS(p, "      <div id=\"ak-box\" hidden>\n"
              "        <canvas class=\"chart\" id=\"ak-chart\" aria-label=\"every key of the metric on one scale, one colour a key; the legend below lists them\"></canvas>\n"
              "        <div class=\"sub\" id=\"ak-hover\"></div>\n"
              "        <div class=\"ak-head\"><input type=\"search\" id=\"ak-filter\" maxlength=\"63\" spellcheck=\"false\" autocomplete=\"off\" placeholder=\"filter the keys listed\" aria-label=\"filter the keys listed\" hidden> <span class=\"sub\" id=\"ak-rule\"></span> <button type=\"button\" class=\"dt-reset\" id=\"ak-all\" hidden>show every key</button></div>\n"
              "        <div class=\"ak-legend\" id=\"ak-legend\" role=\"list\" aria-label=\"every key drawn, its colour and its latest value\"></div>\n"
              "        <button type=\"button\" class=\"dt-reset\" id=\"ak-more\" hidden>show more</button>\n"
              "      </div>\n");
    /* Kept with the page's prefs; the default is one key, as before. */
    WT_HAS(p, "    S.on = H.prefGet(\"act.allkeys\") === true;\n");
    WT_HAS(p, "      H.prefSet(\"act.allkeys\", S.on ? true : null);\n");
    WT_HAS(p, JS_MODEBTN);
    WT_HAS(p, JS_INIT);
    WT_HAS(p, JS_MAIN);
    /* The picked entry is brass and bold, never the accent. */
    WT_HAS(p, "button.ak-key.on { border-color: var(--brass); font-weight: 700; }");
}

static void test_reading_and_painting(void) {
    const char *p = page();
    WT_HAS(p, JS_TAKE);
    WT_HAS(p, JS_LAND);
    WT_HAS(p, JS_ROWOF);
    WT_HAS(p, JS_LOAD);
    WT_HAS(p, JS_PAINT);
    WT_HAS(p, JS_PAINTMARKS);
    WT_HAS(p, JS_WANTBAND);
    WT_HAS(p, JS_ISBANDED);
    WT_HAS(p, JS_STAMP);
    /* The caption's parts, each where the grammar puts it (R9): the
     * shared scale and its top; the band's state; the sort. */
    WT_HAS(p, "      scaleText = !pn ? \"\" : \"shared scale, top \" + H.fmt(hi2) + \" \" + m.unit + \", \" +\n"
              "        (banded ? \"band \xc2\xb1\" + H.sens().toFixed(1) + \" sd for \" + S.pick\n"
              "                : pi >= 0 ? \"no band for \" + S.pick + \" yet\"\n"
              "                : \"no band: it is one key's, pick a key for its\") +\n"
              "        \", sorted by latest value\" +\n"
              "        (S.rows.length > LINES ? \", lines for the \" + LINES + \" largest, the other \" +\n"
              "                                 (S.rows.length - LINES) + \" as their range a cell\" : \"\");\n");
    WT_HAS(p, "      scaleText = pn ? \"0/1, one row a key, sorted by cells present\" : \"\";\n");
    /* R5's states, in words. */
    WT_HAS(p, "      state: head.out_of_scope === true ? \"not in the \" + H.scopeWord(H.scope()) + \" scope\"\n"
              "           : !S.rows.length ? (S.loading && !S.done ? \"\" : \"no \" + (head.keykind || \"key\") + \" seen yet\")\n"
              "           : !pn ? \"no data\"\n"
              "           : !presence && S.shrunk ? S.shrunk\n"
              "           : !presence && pi >= 0 && !isBanded(band) ? \"warming\" : \"\" }) +\n");
    /* R11 and R4, through glyph.js's own. */
    WT_HAS(p, "      var sc = glyph.shared(S.rows, S.scaleOf === S.of ? S.scale : null);\n");
    WT_HAS(p, "      var gw = glyph.win(t0 === null ? [] : [[t0, 0], [t1, 0]], head.from, head.to);\n");
}

static void test_legend(void) {
    const char *p = page();
    WT_HAS(p, JS_LEGEND);
    WT_HAS(p, JS_PICK);
    WT_HAS(p, JS_HOT);
    WT_HAS(p, JS_ROWAT);
    WT_HAS(p, JS_INDEXOFKEY);
    /* The legend's rows are in rank()'s order, which is the graph's. */
    WT_HAS(p, "    S.rows = rank(R.rows);\n");
    /* The filter and "show more": the page's own search input, kept
     * out of the prefs (test_prefs.c), a chunk of entries at a time. */
    WT_HAS(p, "    $(\"ak-filter\").addEventListener(\"input\", function () {\n"
              "      S.filter = $(\"ak-filter\").value.trim();\n"
              "      S.shown = LEGEND_CHUNK;\n"
              "      if (S.m) legend(S.m);\n"
              "    });\n");
    WT_HAS(p, "    $(\"ak-more\").addEventListener(\"click\", function () {\n"
              "      S.shown += LEGEND_CHUNK;\n"
              "      if (S.m) legend(S.m);\n"
              "    });\n");
    WT_HAS(p, "    var hits = filterRows(S.rows, S.filter), n = Math.min(hits.length, S.shown);\n");
    /* The read: one request at a time, dropped when the window changed
     * (S.gen) and stopped when the Activity view is not the one shown;
     * what bounds it named. */
    WT_HAS(p, "        if (gen !== S.gen) return;\n"
              "        if (!S.on || !H.active()) { S.gen++; S.loading = false; S.done = false; return; }\n");
    WT_HAS(p, "        var cut = R.rows.length >= KEYS_MAX && j.more === true ? \"bound\"\n"
              "                : more && Date.now() - R.t0 >= READ_MS ? \"time\"\n"
              "                : j.more === true && !more ? \"stopped\" : \"\";\n");
    WT_HAS(p, "        if (first && Date.now() - R.drawn >= DRAW_MS) { R.drawn = Date.now(); land(m, R, false, \"\"); }\n");
    /* The rule is stated beside the legend. */
    WT_HAS(p, "                  : \"every key by its latest value, largest first\") +\n");
    /* A device's entry offers the drawer, the page's own way in. */
    WT_HAS(p, "        o.addEventListener(\"click\", function () { H.openDrawer(r.key); });\n");
    /* Untrusted keys: this module writes no markup, makes no control
     * and sets no attribute; a key leaves only as a parameter. */
    const char *a = strstr(p, "// slothweb: every key of a metric on the Activity page's one graph");
    const char *e = a ? strstr(a, "window.SlothAllKeys = { init: init, main: main,") : NULL;
    WT_ASSERT(a && e);
    if (a && e) {
        size_t n = (size_t)(e - a);
        char *js = malloc(n + 1);
        WT_ASSERT(js != NULL);
        if (js) {
            memcpy(js, a, n);
            js[n] = '\0';
            WT_LACKS(js, "innerHTML");
            WT_LACKS(js, "insertAdjacentHTML");
            WT_LACKS(js, "document.write");
            WT_LACKS(js, "setAttribute");
            WT_LACKS(js, "eval(");
            WT_HAS(js, "if (after !== null) p += \"&after=\" + encodeURIComponent(after);");
            /* --signal is the now mark's and nothing else's (P6). */
            int sig = 0;
            for (const char *q = js; (q = strstr(q, "\"--signal\"")) != NULL; q++) sig++;
            WT_EQ(sig, 1);
            /* R8: no gradient, no shadow, no hatch. */
            WT_LACKS(js, "createLinearGradient");
            WT_LACKS(js, "shadowBlur");
            WT_LACKS(js, "createPattern");
            free(js);
        }
    }
}

void run_allkeys_tests(void) {
    WT_RUN(test_parameters);
    WT_RUN(test_parameters_generated);
    WT_RUN(test_cells);
    WT_RUN(test_answer_shape);
    WT_RUN(test_paging);
    WT_RUN(test_every_key_is_walked);
    WT_RUN(test_a_full_answer_pages);
    WT_RUN(test_route_and_scope);
    WT_RUN(test_worst_page_from_memory);
    WT_RUN(test_walk_of_8192_keys_from_memory);
#ifdef WITH_SQLITE
    WT_RUN(test_worst_page_from_the_store);
    WT_RUN(test_keys_are_the_stores_too);
    WT_RUN(test_walk_of_8192_keys_from_the_store);
#endif
    WT_RUN(test_the_page_carries_the_ported_js);
    WT_RUN(test_legend_order);
    WT_RUN(test_n_of_m_caption);
    WT_RUN(test_tier_of);
    WT_RUN(test_cols_for);
    WT_RUN(test_legend_filter);
    WT_RUN(test_strip_rows);
    WT_RUN(test_colour_is_the_keys_hash);
    WT_RUN(test_lines_states);
    WT_RUN(test_lines_isolated_point);
    WT_RUN(test_lines_focus);
    WT_RUN(test_lines_band);
    WT_RUN(test_lines_fold_into_a_range);
    WT_RUN(test_lines_labels);
    WT_RUN(test_lines_read_in_greyscale);
    WT_RUN(test_frame);
    WT_RUN(test_strips);
    WT_RUN(test_wiring);
    WT_RUN(test_reading_and_painting);
    WT_RUN(test_legend);
}
