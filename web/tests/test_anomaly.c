/* The anomaly engine (#161, M3), rule by rule, from seeded state: the
 * spec's "every rule has a seeded-state test" (§6), on the pattern of
 * tests/test_alerts.c.
 *
 * Baselines are seeded with web_baseline_feed(), the baseline's own
 * entry point; the minute and hour buckets "now" go in through
 * web_anomaly_rows(), the call web_tsdb makes with every batch it takes
 * off the rollup's queue; and the clock moves only through
 * web_anomaly_step(). The wiring of the real framer, decoder, rollup and
 * store thread into these is test_replay.c's job. Every absence
 * asserted here was seen to fail under the mutation its comment names. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

#include "web_anomaly.h"
#include "web_baseline.h"
#include "web_ident.h"
#include "web_ingest.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_rollup.h"
#include "web_store.h"
#include "sdb_gen.h"
#include "web_oui.h"
#include "web_slothdb.h"
#include "wtest.h"

#define HOUR 3600LL
#define WEEK (168LL * HOUR)
#define THU0 1792627200LL                 /* Thursday 2026-10-22 00:00 UTC */
#define T0   (THU0 + 14 * HOUR)           /* "now": Thursday 14:00 */

static char g_dir[64];
static web_store_t    st;
static int            have_st;
static web_baseline_t bl;
static web_ident_t    idt;
static web_anomaly_t  an;
static web_anom_cfg_t g_cfg;
static long long      g_mono;

static long long mono_fn(void *ctx) { (void)ctx; return g_mono; }

static void db_path(char *p, size_t n) { snprintf(p, n, "%s/a.db", g_dir); }

static void engine(void) {
    WT_EQ(web_baseline_init(&bl, 256), 0);
    g_cfg.bl = &bl;
    WT_EQ(web_anomaly_init(&an, 32, &g_cfg), 0);
}

/* store: open a slothweb.db (in an SQLite build); live: NULL counts
 * every minute as observed. */
static void fx(int store, web_live_t *live) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/slothweb-anomaly-XXXXXX");
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    have_st = 0;
    if (store && web_store_available()) {
        char p[128], err[512];
        db_path(p, sizeof(p));
        WT_EQ(web_store_open(&st, p, err, sizeof(err)), 0);
        have_st = 1;
    }
    WT_EQ(web_ident_init(&idt, 64, 64), 0);
    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.store = have_st ? &st : NULL;
    g_cfg.live = live;
    g_cfg.ident = &idt;
    g_cfg.mono = mono_fn;
    g_cfg.max_keys = 64;
    g_mono = 0;
    engine();
}

/* A restart: a new engine and baseline on the same store and identity
 * tables, restored from the store. */
static void restart(long long now) {
    web_anomaly_destroy(&an);
    web_baseline_destroy(&bl);
    engine();
    WT_EQ(web_anomaly_restore(&an, now), 0);
}

static void fx_done(void) {
    web_anomaly_destroy(&an);
    web_baseline_destroy(&bl);
    web_ident_destroy(&idt);
    if (have_st) web_store_close(&st);
    char p[128], s[160];
    db_path(p, sizeof(p));
    unlink(p);
    snprintf(s, sizeof(s), "%s-wal", p); unlink(s);
    snprintf(s, sizeof(s), "%s-shm", p); unlink(s);
    rmdir(g_dir);
}

static void row(int tier, int metric, const char *key, long long t,
                double sum, unsigned long n, double max) {
    web_qrow_t r;
    memset(&r, 0, sizeof(r));
    r.tier = tier;
    r.metric = metric;
    snprintf(r.key, sizeof(r.key), "%s", key);
    r.t = t;
    r.sum = sum;
    r.n = n;
    r.min = n ? sum / (double)n : 0;
    r.max = max;
    web_anomaly_rows(&an, &r, 1);
}

static void gauge(int metric, const char *key, long long t, double v) {
    row(WEB_TIER_MINUTE, metric, key, t, v, 1, v);
}

static void counter(int metric, const char *key, long long t, double v) {
    row(WEB_TIER_MINUTE, metric, key, t, v, 1, v);
}

static void step(long long t) { web_anomaly_step(&an, t); }

/* Weeks of one cell: fed at hour h minus k weeks, oldest first. */
static void seed(int metric, const char *key, long long h, const double *v,
                 int n) {
    for (int i = 0; i < n; i++)
        web_baseline_feed(&bl, metric, key, h - (long long)(n - i) * WEEK,
                          v[i], 1);
}

static const char *list(long long now) {
    static char body[65536 - 1024];
    size_t n = web_anomaly_json(&an, now, now - WEB_ANOM_KEEP_S, -1, body,
                                sizeof(body));
    WT_ASSERT(n > 0);
    body[n < sizeof(body) ? n : sizeof(body) - 1] = '\0';
    return body;
}

/* The newest episode of (rule, key), or a free one standing for none,
 * so a test can read it either way. */
static web_anom_ep_t *ep(int rule, const char *key) {
    static web_anom_ep_t none;
    web_anom_ep_t *best = NULL;
    for (int i = 0; i < an.cap; i++) {
        web_anom_ep_t *e = &an.ep[i];
        if (e->state != WEB_EP_FREE && e->rule == rule && !strcmp(e->key, key) &&
            (!best || e->id > best->id))
            best = e;
    }
    memset(&none, 0, sizeof(none));
    return best ? best : &none;
}

static int count_rule(int rule) {
    int n = 0;
    for (int i = 0; i < an.cap; i++)
        n += an.ep[i].state != WEB_EP_FREE && an.ep[i].rule == rule;
    return n;
}

/* host.conns at T0's hour: three weeks of 5, a cell with var 0. */
static const double FIVE3[] = { 5, 5, 5 };

/* Minutes of a gauge from T0: v[i] in minute i, then the step that
 * closes it. */
static void gauge_run(int metric, const char *key, const double *v, int n) {
    step(T0);
    for (int i = 0; i < n; i++) {
        long long t = T0 + i * 60;
        if (!isnan(v[i])) gauge(metric, key, t, v[i]);
        step(t + 60);
    }
}

/* ── A1 ──────────────────────────────────────────────────────────────── */

static void test_a1_fires_on_sustained_burst(void) {
    fx(0, NULL);
    seed(WM_HOST_CONNS, "10.0.0.5", T0, FIVE3, 3);
    const double v[] = { 500, 500, 500 };
    gauge_run(WM_HOST_CONNS, "10.0.0.5", v, 3);
    const char *j = list(T0 + 180);
    WT_HAS(j, "\"kind\":\"rate\"");
    WT_HAS(j, "\"rule\":\"A1\"");
    WT_HAS(j, "\"metric\":\"host.conns\"");
    WT_HAS(j, "\"open\":true");
    /* The evidence names metric[key] with both brackets. */
    WT_HAS(j, "host.conns[10.0.0.5] z=495.0 value=500 baseline=5");
    web_anom_ep_t *e = ep(WEB_ANOM_A1_RATE, "10.0.0.5");
    WT_ASSERT(e->state == WEB_EP_OPEN && e->hit_streak == 3);
    WT_EQ(e->first_seen, T0 + 60);
    fx_done();
}

/* Two burst minutes are not three: nothing opens, and the builder is
 * dropped by the quiet minute after. Seen red with A1's streak at 2. */
static void test_a1_two_minutes_never_open(void) {
    fx(0, NULL);
    seed(WM_HOST_CONNS, "10.0.0.5", T0, FIVE3, 3);
    const double v[] = { 500, 500, 5, 5 };
    gauge_run(WM_HOST_CONNS, "10.0.0.5", v, 4);
    WT_EQ(an.st.opened, 0UL);
    WT_HAS(list(T0 + 240), "\"anomalies\":[]");
    fx_done();
}

/* A gauge with no row in a minute was not measured: the streak breaks
 * (burst, burst, nothing, burst never reaches three). */
static void test_a1_gauge_gap_breaks_streak(void) {
    fx(0, NULL);
    seed(WM_HOST_CONNS, "10.0.0.5", T0, FIVE3, 3);
    const double v[] = { 500, 500, NAN, 500 };
    gauge_run(WM_HOST_CONNS, "10.0.0.5", v, 4);
    WT_EQ(an.st.opened, 0UL);
    web_anom_ep_t *e = ep(WEB_ANOM_A1_RATE, "10.0.0.5");
    WT_ASSERT(e->state == WEB_EP_BUILDING && e->hit_streak == 1);
    fx_done();
}

/* The quiet stream: a constant history (var 0) and live values that
 * jitter by one either side. Nothing at all is listed. Seen red with
 * the sd floor removed (sd = sqrt(var)): every minute off 5 had z
 * infinite. */
static void test_a1_quiet_jitter_fires_nothing(void) {
    fx(0, NULL);
    seed(WM_HOST_CONNS, "10.0.0.6", T0, FIVE3, 3);
    const double v[] = { 4, 6, 5, 6, 4, 6, 6, 4, 5, 6 };
    gauge_run(WM_HOST_CONNS, "10.0.0.6", v, 10);
    WT_HAS(list(T0 + 600), "\"anomalies\":[]");
    WT_EQ(count_rule(WEB_ANOM_A1_RATE), 0);
    fx_done();
}

/* A counter with a baseline and no row counted nothing, and nothing is
 * far out of band for a host that asks 30 names a minute at this hour
 * every week. Every week alike, the spread is a count's own: Poisson,
 * sd = sqrt(30), so z = -30 / 5.48. */
static void test_a1_silent_counter_scores_zero(void) {
    fx(0, NULL);
    const double v[] = { 30, 30, 30, 30 };
    seed(WM_DNS_QUERIES, "10.0.0.8", T0, v, 4);
    step(T0);
    for (int i = 0; i < 3; i++) step(T0 + (i + 1) * 60);
    web_anom_ep_t *e = ep(WEB_ANOM_A1_RATE, "10.0.0.8");
    WT_ASSERT(e->state == WEB_EP_OPEN);
    WT_HAS(list(T0 + 180), "dns.queries[10.0.0.8] z=-5.5 value=0 "
                           "baseline=30\xc2\xb1" "5.48");
    fx_done();
}

/* The same silence in minutes slothweb did not observe (the socket
 * connected, no record for longer than the A10 limit) is not scored:
 * no A1 for the counter. Seen red with minute_observed() returning 1. */
static void test_a1_unobserved_minutes_are_not_scored(void) {
    web_live_t live;
    web_live_init(&live, "unix:/test/sloth.sock");
    web_live_sock_connected(&live, 0);
    fx(0, &live);
    const double v[] = { 30, 30, 30, 30 };
    seed(WM_DNS_QUERIES, "10.0.0.8", T0, v, 4);
    g_mono = 10LL * 60 * 1000;               /* ten minutes connected, mute */
    step(T0);
    for (int i = 0; i < 4; i++) {
        g_mono += 60000;
        step(T0 + (i + 1) * 60);
    }
    WT_EQ(count_rule(WEB_ANOM_A1_RATE), 0);
    WT_ASSERT(an.st.minutes_unobserved >= 3);
    fx_done();
    web_live_destroy(&live);
}

/* A bucket closed in two parts (an eviction and a return) is scored as
 * their sum: 30 + 30 is this host's usual 60 a minute. Scored as two
 * buckets of 30 each it is z = -30 / sqrt(60) = -3.9. Seen red with
 * agg_put() never merging. */
static void test_a1_bucket_in_two_parts_is_one_bucket(void) {
    fx(0, NULL);
    const double v[] = { 60, 60, 60 };
    seed(WM_DNS_QUERIES, "10.0.0.9", T0, v, 3);
    step(T0);
    for (int i = 0; i < 4; i++) {
        long long t = T0 + i * 60;
        counter(WM_DNS_QUERIES, "10.0.0.9", t, 30);
        counter(WM_DNS_QUERIES, "10.0.0.9", t, 30);
        step(t + 60);
    }
    WT_EQ(count_rule(WEB_ANOM_A1_RATE), 0);
    fx_done();
}

/* The previous slice scored at most the 256 most recently seen keys of
 * a metric, half the default device cap. Every row of the minute is
 * scored: 300 hosts bursting open 300 episodes. */
static void test_a1_scores_every_key(void) {
    fx(0, NULL);
    web_anomaly_destroy(&an);
    web_baseline_destroy(&bl);
    WT_EQ(web_baseline_init(&bl, 1024), 0);
    g_cfg.bl = &bl;
    WT_EQ(web_anomaly_init(&an, WEB_ANOM_CAP, &g_cfg), 0);
    char k[300][16];
    for (int i = 0; i < 300; i++) {
        snprintf(k[i], sizeof(k[i]), "10.1.%d.%d", i / 250, i % 250 + 1);
        seed(WM_HOST_CONNS, k[i], T0, FIVE3, 3);
    }
    step(T0);
    for (int m = 0; m < 3; m++) {
        for (int i = 0; i < 300; i++) gauge(WM_HOST_CONNS, k[i], T0 + m * 60, 500);
        step(T0 + (m + 1) * 60);
    }
    WT_EQ(count_rule(WEB_ANOM_A1_RATE), 300);
    WT_EQ(an.st.opened, 300UL);
    fx_done();
}

/* ── lifecycle ───────────────────────────────────────────────────────── */

static void open_a1(const char *key) {
    seed(WM_HOST_CONNS, key, T0, FIVE3, 3);
    step(T0);
    for (int i = 0; i < 3; i++) {
        gauge(WM_HOST_CONNS, key, T0 + i * 60, 500);
        step(T0 + (i + 1) * 60);
    }
}

/* Open after a quiet minute, closed after the second (CLEAR_TICKS).
 * "Still open after one" seen red with WEB_ANOM_CLEAR_TICKS at 1. */
static void test_episode_closes_after_two_quiet_minutes(void) {
    fx(0, NULL);
    open_a1("10.0.0.12");
    gauge(WM_HOST_CONNS, "10.0.0.12", T0 + 180, 5);
    step(T0 + 240);
    web_anom_ep_t *e = ep(WEB_ANOM_A1_RATE, "10.0.0.12");
    WT_ASSERT(e->state == WEB_EP_OPEN && e->clear_streak == 1);
    gauge(WM_HOST_CONNS, "10.0.0.12", T0 + 240, 5);
    step(T0 + 300);
    WT_ASSERT(e->state == WEB_EP_CLOSED);
    WT_HAS(list(T0 + 300), "\"open\":false");
    fx_done();
}

/* The audit's case: a closed episode was deleted one minute after it
 * closed. It is listed 59 minutes after, not 61 (the default window is
 * an hour), and kept until WEB_ANOM_KEEP_S. "Gone at 61" seen red with
 * the since filter removed from web_anomaly_json(). */
static void test_closed_episode_listed_for_its_window(void) {
    fx(0, NULL);
    open_a1("10.0.0.12");
    long long t = T0 + 180;
    for (int i = 0; i < 2; i++, t += 60) {
        gauge(WM_HOST_CONNS, "10.0.0.12", t, 5);
        step(t + 60);
    }
    web_anom_ep_t *e = ep(WEB_ANOM_A1_RATE, "10.0.0.12");
    WT_ASSERT(e->state == WEB_EP_CLOSED);
    long long closed = e->last_seen;
    for (; t < closed + 61 * 60; t += 60) {
        gauge(WM_HOST_CONNS, "10.0.0.12", t, 5);
        step(t + 60);
    }
    static char body[65536 - 1024];
    WT_ASSERT(web_anomaly_json(&an, closed + 59 * 60, closed + 59 * 60 - 3600,
                               -1, body, sizeof(body)) > 0);
    WT_HAS(body, "\"key\":\"10.0.0.12\"");
    WT_ASSERT(web_anomaly_json(&an, closed + 61 * 60, closed + 61 * 60 - 3600,
                               -1, body, sizeof(body)) > 0);
    WT_LACKS(body, "\"key\":\"10.0.0.12\"");
    WT_ASSERT(e->state == WEB_EP_CLOSED);         /* kept, only not listed */
    fx_done();
}

/* A rule that holds again after its episode closed starts a new one,
 * which must earn three minutes afresh. Seen red with active_locked()
 * also matching closed episodes: one burst minute reopened the old one
 * with its old first_seen. */
static void test_reopen_needs_a_fresh_streak(void) {
    fx(0, NULL);
    open_a1("10.0.0.12");
    long long t = T0 + 180;
    for (int i = 0; i < 2; i++, t += 60) {
        gauge(WM_HOST_CONNS, "10.0.0.12", t, 5);
        step(t + 60);
    }
    web_anom_ep_t *old = ep(WEB_ANOM_A1_RATE, "10.0.0.12");
    long long old_id = old->id, old_first = old->first_seen;
    WT_ASSERT(old->state == WEB_EP_CLOSED);
    gauge(WM_HOST_CONNS, "10.0.0.12", t, 500);
    step(t + 60);
    web_anom_ep_t *e = ep(WEB_ANOM_A1_RATE, "10.0.0.12");
    WT_ASSERT(e->id != old_id);
    WT_ASSERT(e->state == WEB_EP_BUILDING);
    WT_ASSERT(e->first_seen != old_first);
    WT_EQ(an.st.opened, 1UL);
    for (int i = 0; i < 2; i++) {
        t += 60;
        gauge(WM_HOST_CONNS, "10.0.0.12", t, 500);
        step(t + 60);
    }
    WT_ASSERT(e->state == WEB_EP_OPEN);
    WT_EQ(an.st.opened, 2UL);
    fx_done();
}

/* A full table: a closed episode makes room; an open or building one
 * is never pushed out (builders evicting each other would never let
 * either reach its streak), so the newcomer is dropped and counted. */
static void test_full_table_keeps_open_episodes(void) {
    fx(0, NULL);
    an.cap = 2;
    open_a1("10.0.0.1");
    seed(WM_HOST_CONNS, "10.0.0.2", T0, FIVE3, 3);
    seed(WM_HOST_CONNS, "10.0.0.3", T0, FIVE3, 3);
    long long t = T0 + 180;
    for (int i = 0; i < 3; i++, t += 60) {
        gauge(WM_HOST_CONNS, "10.0.0.1", t, 500);
        gauge(WM_HOST_CONNS, "10.0.0.2", t, 500);
        gauge(WM_HOST_CONNS, "10.0.0.3", t, 500);
        step(t + 60);
    }
    WT_ASSERT(ep(WEB_ANOM_A1_RATE, "10.0.0.1")->state == WEB_EP_OPEN);
    WT_ASSERT(ep(WEB_ANOM_A1_RATE, "10.0.0.2")->state == WEB_EP_OPEN);
    WT_ASSERT(ep(WEB_ANOM_A1_RATE, "10.0.0.3")->state == WEB_EP_FREE);
    WT_ASSERT(an.st.dropped >= 3);
    fx_done();
}

/* /api/anomalies' worst case: every slot an open episode with an IPv6
 * key and evidence that expands six-fold. The answer still fits the
 * connection's body, stops with "more":true and counts what it left
 * out. The previous slice answered 503 past 276 episodes. Seen red with
 * the room check removed (the list overflowed and answered 0). */
static void test_worst_case_listing_fits(void) {
    fx(0, NULL);
    web_anomaly_destroy(&an);
    WT_EQ(web_anomaly_init(&an, WEB_ANOM_CAP, &g_cfg), 0);
    for (int i = 0; i < an.cap; i++) {
        web_anom_ep_t *e = &an.ep[i];
        e->id = i + 1;
        e->state = WEB_EP_OPEN;
        e->rule = WEB_ANOM_A1_RATE;
        e->metric = WM_HOST_CONNS;
        snprintf(e->key, sizeof(e->key),
                 "2001:db8:aaaa:bbbb:cccc:dddd:%04x:%04x", i, i);
        memset(e->evidence, '<', WEB_ANOM_EVIDENCE_MAX);
        e->evidence[WEB_ANOM_EVIDENCE_MAX] = '\0';
        e->score = e->peak = 100;
        e->first_seen = e->last_seen = 9999999999LL;
    }
    static char body[65536 - 1024];
    size_t n = web_anomaly_json(&an, 9999999999LL, 0, -1, body, sizeof(body));
    WT_ASSERT(n > 0 && n < sizeof(body));
    if (n >= sizeof(body)) n = sizeof(body) - 1;
    body[n] = '\0';
    WT_HAS(body, "\"more\":true");
    WT_LACKS(body, "\"omitted\":0}");
    WT_ASSERT(n >= 2 && body[n - 1] == '\n' && body[n - 2] == '}');
    /* One episode can never be larger than the bound the list uses. */
    char one[WEB_ANOM_EP_JSON_MAX + 1];
    web_jw_t w;
    web_jw_init(&w, one, sizeof(one));
    web_anomaly_ep_json(&w, &an.ep[0]);
    WT_EQ(w.overflow, 0);
    fx_done();
}

/* kind= selects §6 kinds (A5 and A6 are both "ident"); since= hides
 * closed episodes older than it but never open ones. Seen red with the
 * kind filter removed, and separately the since filter. */
static void test_listing_filters(void) {
    fx(0, NULL);
    an.ep[0] = (web_anom_ep_t){ .id = 1, .state = WEB_EP_OPEN,
        .rule = WEB_ANOM_A6_NAMES, .metric = -1, .key = "10.0.0.1",
        .first_seen = 100, .last_seen = 100 };
    an.ep[1] = (web_anom_ep_t){ .id = 2, .state = WEB_EP_CLOSED,
        .rule = WEB_ANOM_A1_RATE, .metric = WM_HOST_CONNS, .key = "10.0.0.2",
        .first_seen = 100, .last_seen = 200 };
    static char b[65536 - 1024];
    WT_ASSERT(web_anomaly_json(&an, 1000, 150, web_anomaly_kind_find("ident"),
                               b, sizeof(b)) > 0);
    WT_HAS(b, "\"key\":\"10.0.0.1\"");
    WT_LACKS(b, "\"key\":\"10.0.0.2\"");
    WT_ASSERT(web_anomaly_json(&an, 1000, 250, -1, b, sizeof(b)) > 0);
    WT_HAS(b, "\"key\":\"10.0.0.1\"");          /* open: always listed */
    WT_LACKS(b, "\"key\":\"10.0.0.2\"");
    WT_ASSERT(web_anomaly_json(&an, 1000, 150, -1, b, sizeof(b)) > 0);
    WT_HAS(b, "\"key\":\"10.0.0.2\"");
    /* "vendor" is A4's (M4), last so every M3 index stands. */
    WT_EQ(web_anomaly_kind_find("vendor"), 8);
    WT_EQ(web_anomaly_kind_find("vendors"), -1);
    fx_done();
}

/* Changes since a sequence number, for the SSE "anomaly" event: an
 * episode that opens and then closes is reported each time, and nothing
 * between. "Nothing" seen red with the seq test relaxed to >=. */
static void test_changes_feed(void) {
    fx(0, NULL);
    open_a1("10.0.0.12");
    web_anom_ep_t out[4];
    unsigned long long latest;
    int n = web_anomaly_changes(&an, 0, out, 4, &latest);
    WT_EQ(n, 1);
    WT_ASSERT(out[0].state == WEB_EP_OPEN);
    unsigned long long seen = latest;
    WT_EQ(web_anomaly_changes(&an, seen, out, 4, &latest), 0);
    long long t = T0 + 180;
    for (int i = 0; i < 2; i++, t += 60) {
        gauge(WM_HOST_CONNS, "10.0.0.12", t, 5);
        step(t + 60);
    }
    n = web_anomaly_changes(&an, seen, out, 4, &latest);
    WT_EQ(n, 1);
    WT_ASSERT(out[0].state == WEB_EP_CLOSED);
    fx_done();
}

/* More changes than the caller takes: the newest max, oldest first.
 * The slots hold them in the opposite order from their seqs' order of
 * age, so a walk of the slots that stops at max returns the oldest.
 * Seen red with web_anomaly_changes()'s window narrowing replaced by a
 * break (it returned seqs 1..4). */
static void test_changes_returns_the_newest_max(void) {
    fx(0, NULL);
    for (int i = 0; i < 6; i++) {
        an.ep[i] = (web_anom_ep_t){ .id = i + 1, .state = WEB_EP_OPEN,
            .rule = WEB_ANOM_A6_NAMES, .metric = -1, .first_seen = 100,
            .last_seen = 100, .seq = (unsigned long long)(i + 1) };
        snprintf(an.ep[i].key, sizeof(an.ep[i].key), "10.0.0.%d", i + 1);
    }
    an.seq = 6;
    web_anom_ep_t out[4];
    unsigned long long latest;
    WT_EQ(web_anomaly_changes(&an, 0, out, 4, &latest), 4);
    WT_EQ(latest, 6ULL);
    for (int i = 0; i < 4; i++) WT_EQ(out[i].seq, (unsigned long long)(i + 3));
    fx_done();
}

/* The hour pass learns the spread of minutes inside the hour from the
 * minute rows it scored: a gauge alternating 2 and 8 every minute has
 * an hour mean of 5 and a within-hour variance of 9, and the score's
 * sd carries it (sqrt(0 + 9) = 3, where the floor alone said 1). Seen
 * red with within_var() answering -1 (wn 0, sd 1). */
static void test_hour_pass_learns_the_within_hour_spread(void) {
    fx(0, NULL);
    step(T0);
    for (int i = 0; i < 60; i++) {
        double v = i % 2 ? 8 : 2;
        gauge(WM_HOST_CONNS, "10.0.0.20", T0 + i * 60, v);
        /* The hour row comes with the flush of the step that closes
         * the hour, before that step's passes. */
        if (i == 59) row(WEB_TIER_HOUR, WM_HOST_CONNS, "10.0.0.20", T0, 300, 60, 8);
        step(T0 + (i + 1) * 60);
    }
    web_bl_cell_t c[WEB_BL_CELLS];
    WT_EQ(web_baseline_cells(&bl, WM_HOST_CONNS, "10.0.0.20", c), 0);
    const web_bl_cell_t *k = &c[web_bl_cell_index(T0)];
    WT_EQ(k->n, 1);
    WT_EQ(k->wn, 1);
    WT_ASSERT(fabs(k->wvar - 9.0) < 1e-3);
    double sh, w;
    WT_ASSERT(fabs(web_bl_cell_sd(WM_HOST_CONNS, k, &sh, &w) - 3.0) < 1e-3);
    WT_ASSERT(fabs(sh - 1.0) < 1e-9);         /* var 0: the floor */
    fx_done();
}

/* ── A2 ──────────────────────────────────────────────────────────────── */

static void feed(const char *line, long long now) {
    static web_jrec_t r;
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_ident_record(&idt, &r, now);
}

static void probe(const char *mac, long long first_seen, long long now) {
    char b[256];
    snprintf(b, sizeof(b), "{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":"
             "\"%s\",\"first_seen\":%lld,\"last_seen\":%lld,"
             "\"frame_count\":3}", now, mac, first_seen, now);
    feed(b, now);
}

/* A MAC sloth first saw two hours ago is new, once. */
static void test_a2_new_device_reported_once(void) {
    fx(1, NULL);
    step(T0);
    probe("00:11:22:33:44:55", T0 - 2 * HOUR, T0);
    step(T0 + 60);
    web_anom_ep_t *e = ep(WEB_ANOM_A2_NEW, "00:11:22:33:44:55");
    WT_ASSERT(e->state == WEB_EP_OPEN);
    WT_HAS(list(T0 + 60), "first seen by sloth 121 min ago (probe_client)");
    for (int i = 2; i < 8; i++) {
        probe("00:11:22:33:44:55", T0 - 2 * HOUR, T0 + i * 60);
        step(T0 + i * 60);
    }
    WT_EQ(count_rule(WEB_ANOM_A2_NEW), 1);
    WT_ASSERT(e->state == WEB_EP_CLOSED);
    WT_EQ(an.st.opened, 1UL);
    /* Once across a restart too: the reported set is in the store. Seen
     * red with restore_rep() skipped (it was reported again). */
    if (have_st) {
        restart(T0 + 8 * 60);
        step(T0 + 8 * 60);
        probe("00:11:22:33:44:55", T0 - 2 * HOUR, T0 + 8 * 60);
        step(T0 + 9 * 60);
        WT_EQ(an.st.opened, 0UL);
    }
    fx_done();
}

/* sloth resets a client's first_seen to now when it makes the entry
 * (its own restart, or a station evicted and re-learnt), so a MAC with
 * weeks of history arrives with a first_seen of a minute ago. Not new:
 * slothweb's own baseline has known it for four weeks. Seen red with
 * the baseline test removed from a2_old_evidence(). */
static void test_a2_not_new_after_sloth_restarts(void) {
    fx(0, NULL);
    const double one4[] = { 1, 1, 1, 1 };
    seed(WM_DEV_PRESENT, "00:11:22:33:44:99", T0, one4, 4);
    step(T0);
    probe("00:11:22:33:44:99", T0 - 60, T0);
    step(T0 + 60);
    WT_EQ(count_rule(WEB_ANOM_A2_NEW), 0);
    WT_ASSERT(an.st.a2_not_new >= 1);
    /* Asked once: the answer is remembered for the window. */
    unsigned long seen = an.st.a2_not_new;
    probe("00:11:22:33:44:99", T0 - 60, T0 + 60);
    step(T0 + 120);
    WT_EQ(an.st.a2_not_new, seen);
    fx_done();
}

#ifdef WITH_SQLITE
static void store_row(int tier, int metric, const char *key, long long t,
                      double v);

/* The same with nothing in memory (slothweb restarted too, and the
 * baseline was pushed out): the store's rows of the MAC from three days
 * ago are the evidence. A MAC whose oldest row is two hours old is new.
 * Seen red with the store lookup removed from a2_old_evidence(). */
static void test_a2_not_new_by_the_stores_rows(void) {
    fx(1, NULL);
    store_row(WEB_TIER_MINUTE, WM_DEV_FRAMES, "00:11:22:33:44:9a",
              T0 - 3 * 86400, 5);
    store_row(WEB_TIER_MINUTE, WM_DEV_FRAMES, "00:11:22:33:44:9b",
              T0 - 2 * HOUR, 5);
    step(T0);
    probe("00:11:22:33:44:9a", T0 - 60, T0);
    probe("00:11:22:33:44:9b", T0 - 60, T0);
    step(T0 + 60);
    WT_EQ(ep(WEB_ANOM_A2_NEW, "00:11:22:33:44:9a")->state, WEB_EP_FREE);
    WT_EQ(ep(WEB_ANOM_A2_NEW, "00:11:22:33:44:9b")->state, WEB_EP_OPEN);
    WT_ASSERT(an.st.a2_queries >= 2);
    fx_done();
}
#endif

/* The audit's flood: spoofed probe requests, 40 fresh MACs a minute for
 * ten minutes, after an A1 episode closed. The burst is one A2 episode,
 * nothing is dropped, and the A1 episode is still listed. "One episode,
 * none dropped" seen red with WEB_ANOM_A2_BURST raised past 40 (401
 * episodes tried for 32 slots); the A1 episode's survival was seen red
 * only with that and the slot policy reverted together (an oldest-closed
 * pool for every rule), since either alone keeps it. */
static void test_a2_flood_is_one_episode_and_keeps_history(void) {
    fx(1, NULL);
    open_a1("10.0.0.12");
    long long t = T0 + 180;
    for (int i = 0; i < 2; i++, t += 60) {
        gauge(WM_HOST_CONNS, "10.0.0.12", t, 5);
        step(t + 60);
    }
    WT_ASSERT(ep(WEB_ANOM_A1_RATE, "10.0.0.12")->state == WEB_EP_CLOSED);
    for (int m = 0; m < 10; m++, t += 60) {
        for (int k = 0; k < 40; k++) {
            char mac[24];
            snprintf(mac, sizeof(mac), "00:5e:%02x:%02x:00:01", m, k);
            probe(mac, t, t);
        }
        step(t + 60);
    }
    WT_ASSERT(ep(WEB_ANOM_A1_RATE, "10.0.0.12")->state == WEB_EP_CLOSED);
    WT_HAS(list(t), "\"key\":\"10.0.0.12\"");
    WT_EQ(count_rule(WEB_ANOM_A2_NEW), 1);
    WT_EQ(an.st.dropped, 0UL);
    web_anom_ep_t *b = ep(WEB_ANOM_A2_NEW, "");
    WT_ASSERT(b->state == WEB_EP_OPEN);
    WT_HAS(b->evidence, "40 MACs new to sloth in one minute: 00:5e:09:");
    fx_done();
}

/* The slot policy on its own: a table full of closed episodes, all A2
 * but one old A1. A new A2 takes its own rule's oldest, never the A1;
 * and a new A1 (a rule under its share) takes the oldest A2 rather than
 * being dropped. Seen red with new_slot_locked() taking the oldest
 * closed episode of any rule (the A1 went), and separately with the
 * share test removed (the A1 candidate was dropped). */
static void test_slot_policy_keeps_each_rules_history(void) {
    fx(0, NULL);
    an.ep[0] = (web_anom_ep_t){ .id = 1, .state = WEB_EP_CLOSED,
        .rule = WEB_ANOM_A1_RATE, .metric = WM_HOST_CONNS, .key = "10.0.0.12",
        .first_seen = T0 - 7200, .last_seen = T0 - 7200 };
    for (int i = 1; i < an.cap; i++) {
        an.ep[i] = (web_anom_ep_t){ .id = i + 1, .state = WEB_EP_CLOSED,
            .rule = WEB_ANOM_A2_NEW, .metric = -1,
            .first_seen = T0 - 3600 + i, .last_seen = T0 - 3600 + i };
        snprintf(an.ep[i].key, sizeof(an.ep[i].key), "00:5e:00:00:00:%02x", i);
    }
    step(T0);
    probe("00:11:22:33:44:a0", T0 - 60, T0);
    step(T0 + 60);
    WT_ASSERT(ep(WEB_ANOM_A1_RATE, "10.0.0.12")->state == WEB_EP_CLOSED);
    WT_ASSERT(ep(WEB_ANOM_A2_NEW, "00:11:22:33:44:a0")->state == WEB_EP_OPEN);
    WT_ASSERT(ep(WEB_ANOM_A2_NEW, "00:5e:00:00:00:01")->state == WEB_EP_FREE);
    /* Now no A1 history at all: the table is all A2, over its share. */
    an.ep[0].rule = WEB_ANOM_A2_NEW;
    an.ep[0].metric = -1;
    snprintf(an.ep[0].key, sizeof(an.ep[0].key), "00:5e:00:00:00:00");
    seed(WM_HOST_CONNS, "10.0.0.13", T0 + 60, FIVE3, 3);
    gauge(WM_HOST_CONNS, "10.0.0.13", T0 + 60, 500);
    step(T0 + 120);
    WT_ASSERT(ep(WEB_ANOM_A1_RATE, "10.0.0.13")->state == WEB_EP_BUILDING);
    WT_EQ(an.st.dropped, 0UL);
    fx_done();
}

/* A reported set of 16 (--web-max-keys 16), filled by eight MACs a
 * minute twice, each first seen a second after the one before, so none
 * is a burst and the hour's count is at its limit, not over. An hour
 * later (the rolling count empty again) a 17th still gets an episode of
 * its own: the set forgets its oldest first_seen (counted) rather than
 * refuse. The one forgotten moves to the not-one-by-one set, so while
 * sloth still lists it, it is not reported a second time. Seen red with
 * rep_mark() refusing when full (reported_evicted stayed 0 and the
 * oldest was kept), and separately with the move to the
 * not-one-by-one set removed (00:11:22:00:00:00 reported again the
 * next minute, pushing out the next oldest, which was reported again in
 * turn: 19 A2 episodes, 4 evictions). */
static void test_a2_reported_set_evicts_oldest(void) {
    fx(0, NULL);
    web_anomaly_destroy(&an);
    g_cfg.max_keys = WEB_MAX_KEYS_MIN;
    WT_EQ(web_anomaly_init(&an, 32, &g_cfg), 0);
    long long t = T0;
    step(t);
    for (int i = 0; i < 16; i++) {
        char mac[24];
        snprintf(mac, sizeof(mac), "00:11:22:00:00:%02x", i);
        probe(mac, T0 - 100 + i, t);
        if (i % 8 == 7) { step(t + 60); t += 60; }
    }
    WT_EQ(an.st.opened, 16UL);
    WT_EQ(an.st.reported, 16);
    WT_EQ(an.st.reported_evicted, 0UL);
    WT_EQ(ep(WEB_ANOM_A2_NEW, "")->state, WEB_EP_FREE);
    t += 61 * 60;
    step(t);
    probe("00:11:22:00:01:00", t - 60, t);
    step(t + 60);
    t += 60;
    WT_EQ(ep(WEB_ANOM_A2_NEW, "00:11:22:00:01:00")->state, WEB_EP_OPEN);
    WT_HAS(ep(WEB_ANOM_A2_NEW, "00:11:22:00:01:00")->evidence,
           "00:11:22:00:01:00 first seen by sloth 2 min ago (probe_client)");
    WT_EQ(an.st.reported_evicted, 1UL);
    WT_EQ(an.st.reported, 16);
    WT_EQ(ep(WEB_ANOM_A2_NEW, "")->state, WEB_EP_FREE);
    /* The oldest went; sloth still lists it, and it stays unreported. */
    for (int m = 0; m < 3; m++, t += 60) {
        probe("00:11:22:00:00:00", T0 - 100, t);
        step(t + 60);
    }
    WT_EQ(an.st.opened, 17UL);
    WT_EQ(count_rule(WEB_ANOM_A2_NEW), 17);
    WT_EQ(an.st.reported_evicted, 1UL);
    fx_done();
}

/* A full episode table delays a report, never loses it: with room for
 * four episodes, five new MACs in one minute give four episodes and one
 * drop, and the fifth, still listed by sloth, gets its own episode once
 * a slot frees. Seen red with rep_mark() back in a2_scan() before the
 * candidate is touched (the fifth is marked reported, never offered
 * again, and never gets an episode). */
static void test_a2_full_table_delays_not_loses(void) {
    fx(0, NULL);
    web_anomaly_destroy(&an);
    g_cfg.max_keys = WEB_MAX_KEYS_MIN;
    WT_EQ(web_anomaly_init(&an, 4, &g_cfg), 0);
    long long t = T0;
    step(t);
    char mac[24];
    for (int i = 0; i < 5; i++) {
        snprintf(mac, sizeof(mac), "00:11:22:00:02:%02x", i);
        probe(mac, T0 - 100 + i, t);
    }
    step(t + 60);
    t += 60;
    WT_EQ(an.st.opened, 4UL);
    WT_ASSERT(an.st.dropped >= 1UL);
    WT_EQ(an.st.reported, 4);
    int got = 0;
    for (int m = 0; m < 24 * 60 && !got; m++, t += 60) {
        for (int i = 0; i < 5; i++) {
            snprintf(mac, sizeof(mac), "00:11:22:00:02:%02x", i);
            probe(mac, T0 - 100 + i, t);
        }
        step(t + 60);
        got = ep(WEB_ANOM_A2_NEW, "00:11:22:00:02:04")->state != WEB_EP_FREE;
    }
    WT_ASSERT(got);
    WT_EQ(an.st.reported, 5);
    WT_EQ(an.st.opened, 5UL);
    fx_done();
}

/* A MAC both sets have let go may be reported again, and that is the
 * whole of the cost: re-reports are at most the evictions. Identity
 * tables of 16 MACs (so the not-one-by-one set holds 16 too) and a
 * reported set of 16. A0-A15 reported; an hour on, B0-B7 and C0-C7 push
 * all sixteen A out of the reported set into the other; an hour on,
 * D0-D7 push B out, which pushes A0-A7 (the oldest first_seen) out of
 * the other. A0-A7 seen again with their own first_seen are new to
 * slothweb a second time: 8 re-reports, for 32 evictions. Seen red with
 * kv_get2()'s eviction left uncounted (reported_evicted 0, under the 8
 * re-reports it must bound). */
static void test_a2_rereports_bounded_by_evictions(void) {
    fx(0, NULL);
    web_anomaly_destroy(&an);
    web_ident_destroy(&idt);
    WT_EQ(web_ident_init(&idt, 16, 16), 0);
    g_cfg.ident = &idt;
    g_cfg.max_keys = WEB_MAX_KEYS_MIN;
    WT_EQ(web_anomaly_init(&an, 32, &g_cfg), 0);
    char mac[24];
    long long t = T0;
    step(t);
    for (int i = 0; i < 16; i++) {
        snprintf(mac, sizeof(mac), "00:11:0a:00:00:%02x", i);
        probe(mac, T0 - 100 + i, t);
        if (i % 8 == 7) { step(t + 60); t += 60; }
    }
    t += 61 * 60;
    step(t);
    for (int g = 0; g < 2; g++) {
        for (int i = 0; i < 8; i++) {
            snprintf(mac, sizeof(mac), "00:11:%02x:00:00:%02x", 0x0b + g, i);
            probe(mac, t - 60, t);
        }
        step(t + 60);
        t += 60;
    }
    WT_EQ(an.st.reported_evicted, 16UL);
    t += 61 * 60;
    step(t);
    for (int i = 0; i < 8; i++) {
        snprintf(mac, sizeof(mac), "00:11:0d:00:00:%02x", i);
        probe(mac, t - 60, t);
    }
    step(t + 60);
    t += 60;
    WT_EQ(an.st.opened, 40UL);
    for (int i = 0; i < 8; i++) {
        snprintf(mac, sizeof(mac), "00:11:0a:00:00:%02x", i);
        probe(mac, T0 - 100 + i, t);
    }
    step(t + 60);
    unsigned long rereports = an.st.opened - 40UL;
    fprintf(stderr, "  %lu re-reports, %lu evictions\n", rereports,
            an.st.reported_evicted);
    WT_EQ(rereports, 8UL);
    WT_EQ(an.st.dropped, 0UL);
    WT_ASSERT(rereports <= an.st.reported_evicted);
    WT_EQ(an.st.reported_evicted, 32UL);
    WT_EQ(ep(WEB_ANOM_A2_NEW, "")->state, WEB_EP_FREE);
    fx_done();
}

/* A burst's and a trickle's evidence count the MACs judged new in that
 * minute or that hour, exactly: never one counted twice, never one the
 * scan had already settled. Five reported in minute 1 (still listed by
 * sloth every minute after), nine in minute 2 (a burst: "9", not the 14
 * sloth lists), three in minute 3 (the hour at 17, over 16: a trickle
 * fold of "17 ... 3 this minute"). Two MACs named, whole. Seen red with
 * a2_scan()'s reported-set test removed (the burst counted the five
 * again: "14 MACs"), and separately with three MACs named. */
static void test_a2_burst_evidence_counts_exactly(void) {
    fx(0, NULL);
    char mac[24];
    long long t = T0;
    step(t);
    for (int i = 0; i < 5; i++) {
        snprintf(mac, sizeof(mac), "00:11:0e:00:00:%02x", i);
        probe(mac, t - 60, t);
    }
    step(t + 60);
    t += 60;
    WT_EQ(an.st.opened, 5UL);
    for (int i = 0; i < 9; i++) {
        snprintf(mac, sizeof(mac), "00:11:0f:00:00:%02x", i);
        probe(mac, t - 60, t);
    }
    step(t + 60);
    t += 60;
    web_anom_ep_t *b = ep(WEB_ANOM_A2_NEW, "");
    WT_EQ(b->state, WEB_EP_OPEN);
    WT_EQ(strcmp(b->evidence, "9 MACs new to sloth in one minute: "
                              "00:11:0f:00:00:00 00:11:0f:00:00:01"), 0);
    WT_EQ(an.st.a2_in_burst, 9UL);
    for (int i = 0; i < 3; i++) {
        snprintf(mac, sizeof(mac), "00:11:10:00:00:%02x", i);
        probe(mac, t - 60, t);
    }
    step(t + 60);
    t += 60;
    WT_EQ(ep(WEB_ANOM_A2_NEW, ""), b);
    WT_EQ(strcmp(b->evidence, "17 MACs new to sloth in the last hour (over "
                              "16), 3 this minute; latest: 00:11:10:00:00:01 "
                              "00:11:10:00:00:02"), 0);
    WT_EQ(an.st.a2_in_burst, 12UL);
    WT_EQ(an.st.opened, 6UL);
    WT_EQ(ep(WEB_ANOM_A2_NEW, "00:11:10:00:00:00")->state, WEB_EP_FREE);
    fx_done();
}

/* The trickle the per-minute burst test misses: eight spoofed MACs a
 * minute for ten minutes, never more than WEB_ANOM_A2_BURST at once.
 * The first sixteen (the hour's limit) are reported one by one, the
 * other 64 fold into one episode keyed "", which holds while the hour
 * is over the limit and closes once it is not; the reported set takes
 * 16, not 80. Seen red with the rolling-hour test removed from
 * a2_scan() (80 episodes tried for 32 slots, the set filled). */
static void test_a2_trickle_is_one_episode(void) {
    fx(0, NULL);
    long long t = T0;
    step(t);
    for (int m = 0; m < 10; m++, t += 60) {
        for (int k = 0; k < 8; k++) {
            char mac[24];
            snprintf(mac, sizeof(mac), "00:5e:01:%02x:%02x:01", m, k);
            probe(mac, t, t);
        }
        step(t + 60);
    }
    WT_EQ(count_rule(WEB_ANOM_A2_NEW), 17);
    WT_EQ(an.st.dropped, 0UL);
    WT_EQ(an.st.reported, 16);
    WT_EQ(an.st.a2_in_burst, 64UL);
    web_anom_ep_t *b = ep(WEB_ANOM_A2_NEW, "");
    WT_EQ(b->state, WEB_EP_OPEN);
    WT_HAS(b->evidence, "80 MACs new to sloth in the last hour (over 16), "
                        "8 this minute; latest: 00:5e:01:09:06:01 "
                        "00:5e:01:09:07:01");
    /* Quiet for half an hour: the hour is still over, the episode holds. */
    t += 30 * 60;
    step(t);
    WT_EQ(ep(WEB_ANOM_A2_NEW, ""), b);
    WT_EQ(b->state, WEB_EP_OPEN);
    WT_HAS(b->evidence, "0 this minute");
    /* An hour after the last fold, the count is under: it closes. */
    t += 35 * 60;
    step(t);
    WT_EQ(b->state, WEB_EP_CLOSED);
    WT_EQ(count_rule(WEB_ANOM_A2_NEW), 17);
    fx_done();
}

/* --web-max-keys past 4096: a new MAC in identity slot 4501 is scanned.
 * The 4500 before it are recent too (a burst, reported together, an
 * hour before), so only the size of the scan decides. Seen red with the reader's buffer
 * fixed at 4096 rows (the MAC was never reported, and the cut scan was
 * counted in ident_truncated). */
static void test_a2_scans_every_identity_slot(void) {
    fx(0, NULL);
    web_anomaly_destroy(&an);
    web_ident_destroy(&idt);
    WT_EQ(web_ident_init(&idt, 5000, 2500), 0);
    g_cfg.ident = &idt;
    g_cfg.max_keys = 5000;
    WT_EQ(web_anomaly_init(&an, 32, &g_cfg), 0);
    step(T0);
    for (int i = 0; i < 4500; i++) {
        char mac[24];
        snprintf(mac, sizeof(mac), "00:11:%02x:%02x:00:01", i / 256, i % 256);
        probe(mac, T0 - 60, T0);
    }
    step(T0 + 60);
    WT_EQ(ep(WEB_ANOM_A2_NEW, "")->state, WEB_EP_OPEN);
    /* An hour on, so that the burst no longer counts in A2's rolling
     * hour and the new MAC is reported on its own. */
    long long t = T0 + 62 * 60;
    step(t);
    probe("00:11:ff:ff:00:02", t, t);
    step(t + 60);
    WT_EQ(ep(WEB_ANOM_A2_NEW, "00:11:ff:ff:00:02")->state, WEB_EP_OPEN);
    WT_EQ(an.st.ident_truncated, 0UL);
    fx_done();
}

/* Not new: a MAC whose own first_seen is three days old, however
 * recently slothweb started, and a randomised MAC (A5's business).
 * Seen red with the 24 h window removed (from web_ident_firsts()'s
 * since and a2_scan()'s age test together: either alone keeps it), and
 * separately with web_ident_firsts() keeping randomised MACs. */
static void test_a2_old_and_random_macs_are_not_new(void) {
    fx(0, NULL);
    step(T0);
    probe("00:11:22:33:44:56", T0 - 3 * 86400, T0);
    probe("02:11:22:33:44:57", T0 - 60, T0);
    step(T0 + 60);
    WT_EQ(count_rule(WEB_ANOM_A2_NEW), 0);
    fx_done();
}

/* ── A3 ──────────────────────────────────────────────────────────────── */

static void a3_case(int weeks, int present_in_cell) {
    double v[8];
    for (int i = 0; i < weeks; i++) v[i] = present_in_cell ? 1.0 : 0.0;
    seed(WM_DEV_PRESENT, "aa:bb:cc:dd:ee:01", T0, v, weeks);
    step(T0);
    row(WEB_TIER_MINUTE, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:01", T0, 1, 1, 1);
    step(T0 + 60);
}

static void test_a3_fires_for_off_hours_presence(void) {
    fx(0, NULL);
    a3_case(4, 0);
    web_anom_ep_t *e = ep(WEB_ANOM_A3_HOURS, "aa:bb:cc:dd:ee:01");
    WT_ASSERT(e->state == WEB_EP_OPEN);
    WT_HAS(list(T0 + 60), "normally absent (mean 0.00 over 4 weeks)");
    fx_done();
}

/* Three weeks warm the cell but are not A3's four. Seen red with the
 * sc.n < WEB_ANOM_A3_MIN_N test removed (the previous slice's test fed
 * five weeks, so it never saw this boundary). */
static void test_a3_needs_four_weeks(void) {
    fx(0, NULL);
    a3_case(3, 0);
    WT_EQ(count_rule(WEB_ANOM_A3_HOURS), 0);
    fx_done();
}

/* Present in an hour it is normally present: silent. Seen red with the
 * mean test removed. */
static void test_a3_silent_in_normal_hours(void) {
    fx(0, NULL);
    a3_case(4, 1);
    WT_EQ(count_rule(WEB_ANOM_A3_HOURS), 0);
    fx_done();
}

/* ── A5, A6 ──────────────────────────────────────────────────────────── */

static void device(const char *mac, const char *ip, const char *host,
                   long long now) {
    char b[256];
    snprintf(b, sizeof(b), "{\"type\":\"device\",\"ts\":%lld,\"mac\":\"%s\","
             "\"ip\":\"%s\",\"hostname\":\"%s\",\"last_seen\":%lld}", now,
             mac, ip, host, now);
    feed(b, now);
}

/* A randomised MAC carrying the DHCP name of another MAC: A5 for the
 * randomised one only. Seen red with the randomised test dropped from
 * a5_scan() (the fixed MAC got one too). */
static void test_a5_random_mac_with_anothers_name(void) {
    fx(0, NULL);
    step(T0);
    device("00:11:22:33:44:01", "10.0.0.31", "alices-phone", T0);
    device("da:11:22:33:44:02", "10.0.0.32", "Alices-Phone", T0);
    device("da:11:22:33:44:03", "10.0.0.33", "printer", T0);
    step(T0 + 60);
    web_anom_ep_t *e = ep(WEB_ANOM_A5_IDENT, "da:11:22:33:44:02");
    WT_ASSERT(e->state == WEB_EP_OPEN);
    WT_HAS(list(T0 + 60), "also the name of 00:11:22:33:44:01");
    WT_HAS(list(T0 + 60), "\"kind\":\"ident\"");
    WT_ASSERT(ep(WEB_ANOM_A5_IDENT, "00:11:22:33:44:01")->state == WEB_EP_FREE);
    WT_ASSERT(ep(WEB_ANOM_A5_IDENT, "da:11:22:33:44:03")->state == WEB_EP_FREE);
    fx_done();
}

/* A lease that moved to another device names only the device the IP is
 * bound to now: the old MAC's binding to that IP is no longer the IP's.
 * Seen red with web_ident_named() not checking the IP's own MAC. */
static void test_a5_reassigned_lease_names_one_mac(void) {
    fx(0, NULL);
    step(T0);
    feed("{\"type\":\"arp\",\"ts\":1,\"ip\":\"10.0.0.40\",\"mac\":"
         "\"da:00:00:00:00:01\"}", T0);
    feed("{\"type\":\"arp\",\"ts\":1,\"ip\":\"10.0.0.40\",\"mac\":"
         "\"00:00:00:00:00:02\"}", T0);
    feed("{\"type\":\"dhcp_lease\",\"ts\":1,\"ip\":\"10.0.0.40\",\"hostname\":"
         "\"desk\",\"expire\":0}", T0);
    step(T0 + 60);
    WT_EQ(count_rule(WEB_ANOM_A5_IDENT), 0);
    fx_done();
}

static void names(const char *ip, const char *dhcp, const char *mdns,
                  const char *nbns, long long now) {
    char b[256];
    if (dhcp) {
        snprintf(b, sizeof(b), "{\"type\":\"dhcp_lease\",\"ts\":1,\"ip\":\"%s\","
                 "\"hostname\":\"%s\",\"expire\":0}", ip, dhcp);
        feed(b, now);
    }
    if (mdns) {
        snprintf(b, sizeof(b), "{\"type\":\"mdns_service\",\"ts\":1,\"ip\":"
                 "\"%s\",\"host\":\"%s\",\"instance\":\"x\",\"service\":"
                 "\"_ipp._tcp.local\",\"port\":631,\"last_seen\":1}", ip, mdns);
        feed(b, now);
    }
    if (nbns) {
        snprintf(b, sizeof(b), "{\"type\":\"nbns_name\",\"ts\":1,\"ip\":\"%s\","
                 "\"name\":\"%s\",\"suffix\":0,\"last_seen\":1}", ip, nbns);
        feed(b, now);
    }
}

/* Names that agree in normal form (case, ".local", NetBIOS's 15 bytes)
 * are one name; a different one is A6. "Agree" seen red with
 * names_agree() comparing the raw text. */
static void test_a6_name_disagreement(void) {
    fx(0, NULL);
    step(T0);
    names("10.0.0.50", "laptop", "Laptop.local", "LAPTOP", T0);
    names("10.0.0.51", "a-very-long-hostname-x", NULL, "A-VERY-LONG-HOS", T0);
    names("10.0.0.52", "laptop", NULL, "PRINTER", T0);
    step(T0 + 60);
    WT_ASSERT(ep(WEB_ANOM_A6_NAMES, "10.0.0.50")->state == WEB_EP_FREE);
    WT_ASSERT(ep(WEB_ANOM_A6_NAMES, "10.0.0.51")->state == WEB_EP_FREE);
    web_anom_ep_t *e = ep(WEB_ANOM_A6_NAMES, "10.0.0.52");
    WT_ASSERT(e->state == WEB_EP_OPEN);
    WT_HAS(e->evidence, "10.0.0.52: dhcp 'laptop' mdns '' nbns 'PRINTER' disagree");
    fx_done();
}

/* A name with markup is evidence text, escaped where it leaves. Seen
 * red with the evidence written raw in web_anomaly_ep_json(). */
static void test_a6_evidence_is_escaped(void) {
    fx(0, NULL);
    step(T0);
    names("10.0.0.53", "<script>", NULL, "OTHER", T0);
    step(T0 + 60);
    const char *j = list(T0 + 60);
    WT_HAS(j, "\\u003cscript\\u003e");
    WT_LACKS(j, "<script>");
    fx_done();
}

/* ── A7 ──────────────────────────────────────────────────────────────── */

/* windows 10-minute windows of host.conns peaking at base from t, then
 * (last >= 0) one more peaking at last. Returns the time after. */
static long long a7_windows(long long t, int windows, double base,
                            double last) {
    int n = windows + (last >= 0 ? 1 : 0);
    for (int w = 0; w < n; w++)
        for (int m = 0; m < 10; m++, t += 60) {
            double v = w == windows && m == 5 ? last : base;
            row(WEB_TIER_MINUTE, WM_HOST_CONNS, "10.0.0.60", t, v, 1, v);
            step(t + 60);
        }
    return t;
}

/* windows windows peaking at 5, then one at last. */
static void a7_run(int windows, double last) {
    step(T0);
    a7_windows(T0, windows, 5, last);
}

static void test_a7_fires_far_above_its_p95(void) {
    fx(0, NULL);
    a7_run(WEB_ANOM_A7_MIN_WINDOWS, 40);
    web_anom_ep_t *e = ep(WEB_ANOM_A7_FANOUT, "10.0.0.60");
    WT_ASSERT(e->state == WEB_EP_OPEN);
    WT_HAS(list(T0), "host.conns[10.0.0.60] 40 flows at peak in 10 min; its p95 is 6");
    WT_HAS(list(T0), "\"kind\":\"fanout\"");
    fx_done();
}

/* Not enough history, and a value above p95 but not by the margin:
 * silent. The margin case seen red with the WEB_ANOM_A7_FACTOR test
 * removed (12 >= 6 + 5 then fired). */
static void test_a7_silent_without_history_or_margin(void) {
    fx(0, NULL);
    a7_run(WEB_ANOM_A7_MIN_WINDOWS - 1, 40);
    WT_EQ(count_rule(WEB_ANOM_A7_FANOUT), 0);
    fx_done();
    fx(0, NULL);
    a7_run(WEB_ANOM_A7_MIN_WINDOWS, 12);
    WT_EQ(count_rule(WEB_ANOM_A7_FANOUT), 0);
    fx_done();
}

/* A host whose window peak is 2 (p95 2) reaching 5: over twice its p95,
 * but by 3, under WEB_ANOM_A7_MIN_EXCESS. Silent: on a quiet host a
 * factor alone fires for a handful of flows. Seen red with the
 * MIN_EXCESS test removed from a7_close(). */
static void test_a7_silent_below_the_min_excess(void) {
    fx(0, NULL);
    step(T0);
    a7_windows(T0, WEB_ANOM_A7_MIN_WINDOWS, 2, 5);
    WT_EQ(count_rule(WEB_ANOM_A7_FANOUT), 0);
    fx_done();
}

#ifdef WITH_SQLITE
/* The window histograms outlive a restart: the history before it and a
 * spike after it open A7. Seen red with persist_fanout() returning at
 * once, and separately with restore_fan() doing so (no history after
 * the restart: silent). */
static void test_a7_history_survives_restart(void) {
    fx(1, NULL);
    step(T0);
    long long t = a7_windows(T0, WEB_ANOM_A7_MIN_WINDOWS, 5, -1);
    restart(t);
    step(t);
    a7_windows(t, 0, 5, 40);
    WT_ASSERT(ep(WEB_ANOM_A7_FANOUT, "10.0.0.60")->state == WEB_EP_OPEN);
    fx_done();
}
#endif

/* ── A8 ──────────────────────────────────────────────────────────────── */

/* q queries from the client, nx of them answered NXDOMAIN. */
static void a8_run(int q, int nx) {
    step(T0);
    for (int i = 0; i < q; i++) {
        char b[256];
        snprintf(b, sizeof(b), "{\"type\":\"dns\",\"ts\":1,\"src\":"
                 "\"10.0.0.70\",\"qname\":\"x%d.example\",\"qtype\":\"A\","
                 "\"answer\":\"\",\"is_resp\":0}", i);
        feed(b, T0 + i);
        if (i < nx) {
            snprintf(b, sizeof(b), "{\"type\":\"dns\",\"ts\":1,\"src\":"
                     "\"10.0.0.1\",\"qname\":\"X%d.example\",\"qtype\":\"A\","
                     "\"answer\":\"NXDOMAIN\",\"is_resp\":1}", i);
            feed(b, T0 + i + 1);
        }
    }
    step(T0 + 60);
}

/* A client whose answers are mostly NXDOMAIN: joined by qname to the
 * client that asked (the resolver sent them). */
static void test_a8_fires_for_the_client(void) {
    fx(0, NULL);
    a8_run(25, 10);
    web_anom_ep_t *e = ep(WEB_ANOM_A8_DNS, "10.0.0.70");
    WT_ASSERT(e->state == WEB_EP_OPEN);
    WT_HAS(list(T0 + 60), "dns[10.0.0.70] 10 of 25 queries answered NXDOMAIN");
    fx_done();
}

/* 19 queries, every one NXDOMAIN: under A8's 20. Seen red with the
 * WEB_ANOM_A8_MIN_Q test removed. And a share of exactly 30%: silent
 * ("above 30 percent"). */
static void test_a8_needs_twenty_queries_and_the_share(void) {
    fx(0, NULL);
    a8_run(19, 19);
    WT_EQ(count_rule(WEB_ANOM_A8_DNS), 0);
    fx_done();
    fx(0, NULL);
    a8_run(30, 9);
    WT_EQ(count_rule(WEB_ANOM_A8_DNS), 0);
    fx_done();
}

/* ── A9 ──────────────────────────────────────────────────────────────── */

#ifdef WITH_SQLITE
static void store_row(int tier, int metric, const char *key, long long t,
                      double v) {
    web_qrow_t r;
    memset(&r, 0, sizeof(r));
    r.tier = tier;
    r.metric = metric;
    snprintf(r.key, sizeof(r.key), "%s", key);
    r.t = t;
    r.sum = r.min = r.max = v;
    r.n = 1;
    WT_EQ(web_store_write(&st, &r, 1), 0);
}

/* The first flow.ssh row a host has ever had fires; the next minute,
 * with that row on disk, does not touch it again. Two guards hold that
 * (the known set, and the store's earlier row), so it was seen red with
 * both removed together: the known-set test dropped and
 * web_store_any_before() answering 0. */
static void test_a9_first_use(void) {
    fx(1, NULL);
    step(T0);
    store_row(WEB_TIER_MINUTE, WM_FLOW_SSH, "10.0.0.80", T0, 1);
    counter(WM_FLOW_SSH, "10.0.0.80", T0, 1);
    step(T0 + 60);
    web_anom_ep_t *e = ep(WEB_ANOM_A9_PROTO, "10.0.0.80");
    WT_ASSERT(e->state == WEB_EP_OPEN);
    WT_HAS(list(T0 + 60), "flow.ssh[10.0.0.80] first use the store has recorded");
    store_row(WEB_TIER_MINUTE, WM_FLOW_SSH, "10.0.0.80", T0 + 60, 1);
    counter(WM_FLOW_SSH, "10.0.0.80", T0 + 60, 1);
    step(T0 + 120);
    WT_EQ(e->last_seen, T0 + 60);
    fx_done();
}

/* The audit's case: after a restart, a host with months of ssh rows in
 * the store fired A9 again, because "first" meant "no baseline entry".
 * It means "no row before this one". Seen red with
 * web_store_any_before() answering 0. */
static void test_a9_silent_for_history_across_restart(void) {
    fx(1, NULL);
    store_row(WEB_TIER_HOUR, WM_FLOW_SSH, "10.0.0.81", T0 - 90 * 86400, 4);
    restart(T0);
    step(T0);
    store_row(WEB_TIER_MINUTE, WM_FLOW_SSH, "10.0.0.81", T0, 1);
    counter(WM_FLOW_SSH, "10.0.0.81", T0, 1);
    step(T0 + 60);
    WT_EQ(count_rule(WEB_ANOM_A9_PROTO), 0);
    WT_ASSERT(an.st.a9_queries >= 1);
    fx_done();
}

/* ── MAD ─────────────────────────────────────────────────────────────── */

/* 14 weeks at 40 a minute, then fourteen at 200: the EWMA cell (a
 * four-week half-life) says 185.9 with a week-to-week sd of 45.4 (47.4
 * with the count's own Poisson spread), and the 28 same-hour rows have
 * median 120 and MAD 80. */
static void mad_history(const char *key) {
    long long h = T0;
    double v[28];
    for (int k = 28; k >= 1; k--) {
        double per_min = k <= 14 ? 200 : 40;
        store_row(WEB_TIER_HOUR, WM_DNS_QUERIES, key, h - k * WEEK, per_min * 60);
        v[28 - k] = per_min;
    }
    seed(WM_DNS_QUERIES, key, h, v, 28);
}

static void counter_run(const char *key, double v) {
    step(T0);
    for (int i = 0; i < 3; i++) {
        counter(WM_DNS_QUERIES, key, T0 + i * 60, v);
        step(T0 + (i + 1) * 60);
    }
}

/* Back to its old level of 40 a minute: z says out of band (-3.1: the
 * last fourteen weeks were 200), the modified z over 28 weeks says
 * 0.67. Seen red with mad_confirms() returning 1. */
static void test_mad_refutes_a_return_to_normal(void) {
    fx(1, NULL);
    mad_history("10.0.0.90");
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&bl, WM_DNS_QUERIES, "10.0.0.90", T0, 40, &sc), 0);
    WT_ASSERT(fabs(sc.z) >= WEB_ANOM_Z_THRESHOLD);
    counter_run("10.0.0.90", 40);
    WT_EQ(count_rule(WEB_ANOM_A1_RATE), 0);
    WT_ASSERT(an.st.mad_queries >= 1);
    WT_ASSERT(an.st.mad_queries <= 1);      /* cached for the hour */
    fx_done();
}

/* Far from both: the MAD ratio confirms it, and says so. */
static void test_mad_confirms_a_real_burst(void) {
    fx(1, NULL);
    mad_history("10.0.0.91");
    counter_run("10.0.0.91", 600);
    web_anom_ep_t *e = ep(WEB_ANOM_A1_RATE, "10.0.0.91");
    WT_ASSERT(e->state == WEB_EP_OPEN);
    WT_HAS(e->evidence, " mad_z=4.0");
    fx_done();
}

/* The within-hour term in the MAD ratio, on its own. 28 weeks of 95 and
 * 105 a minute, alternating (median 100, MAD 5: sd 7.4 on the
 * normal-equivalent scale), each hour's minutes spread with variance
 * 900 (sd 30). 200 a minute for three minutes: z, with the within term,
 * is 100 / sqrt(var + 900), about 3.3, so A1 asks the MAD ratio; with
 * the same term the modified z is 100 / sqrt(7.4^2 + 900), 3.2, under
 * 3.5, refuted; without it the sd is the floor of 10 and the modified z
 * is 10, confirmed. Seen red with the within term removed from
 * mad_confirms() (the A1 episode opened). */
static void test_mad_counts_the_within_hour_spread(void) {
    fx(1, NULL);
    const char *key = "10.0.0.92";
    for (int k = 28; k >= 1; k--) {
        double per_min = k % 2 ? 95 : 105;
        store_row(WEB_TIER_HOUR, WM_DNS_QUERIES, key, T0 - k * WEEK,
                  per_min * 60);
        WT_EQ(web_baseline_feed_w(&bl, WM_DNS_QUERIES, key, T0 - k * WEEK,
                                  per_min, 900.0, 1), 0);
    }
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&bl, WM_DNS_QUERIES, key, T0, 200, &sc), 0);
    WT_ASSERT(sc.z >= WEB_ANOM_Z_THRESHOLD && sc.z < 3.5);
    WT_ASSERT(fabs(sc.within - 900.0) < 1.0);
    counter_run(key, 200);
    WT_EQ(count_rule(WEB_ANOM_A1_RATE), 0);
    WT_EQ(an.st.mad_queries, 1UL);
    WT_EQ(an.st.mad_skipped, 0UL);
    fx_done();
}

/* ── persistence ─────────────────────────────────────────────────────── */

/* A restart keeps the baselines and the open episode: A1 keeps scoring
 * and the episode keeps its id and first_seen. Seen red with
 * web_anomaly_restore() skipped. */
static void test_state_survives_restart(void) {
    fx(1, NULL);
    open_a1("10.0.0.12");
    /* An hour of rows through the hour pass, so the baseline is written
     * the way production writes it. */
    row(WEB_TIER_HOUR, WM_HOST_CONNS, "10.0.0.13", T0, 50, 10, 5);
    step(T0 + HOUR);
    web_anom_ep_t *e = ep(WEB_ANOM_A1_RATE, "10.0.0.12");
    long long id = e->id, first = e->first_seen;
    int entries = web_baseline_count(&bl);
    WT_ASSERT(entries >= 2);
    web_bl_score_t before, after;
    WT_EQ(web_baseline_score(&bl, WM_HOST_CONNS, "10.0.0.12", T0, 9, &before), 0);
    restart(T0 + HOUR + 10);
    WT_EQ(web_baseline_count(&bl), entries);
    WT_EQ(web_baseline_score(&bl, WM_HOST_CONNS, "10.0.0.12", T0, 9, &after), 0);
    WT_ASSERT(before.mean == after.mean && before.sd == after.sd &&
              before.n == after.n);
    web_bl_cell_t c[WEB_BL_CELLS];
    WT_EQ(web_baseline_cells(&bl, WM_HOST_CONNS, "10.0.0.13", c), 0);
    WT_EQ(c[web_bl_cell_index(T0)].n, 1);
    e = ep(WEB_ANOM_A1_RATE, "10.0.0.12");
    WT_ASSERT(e->id == id && e->first_seen == first);
    WT_HAS(list(T0 + HOUR + 10), "\"key\":\"10.0.0.12\"");
    fx_done();
}

static long long an_raw_int(const char *sql) {
    char p[128];
    db_path(p, sizeof(p));
    sqlite3 *h = NULL;
    long long v = -1;
    sqlite3_stmt *s = NULL;
    if (sqlite3_open(p, &h) == SQLITE_OK &&
        sqlite3_prepare_v2(h, sql, -1, &s, NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW)
        v = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    sqlite3_close(h);
    return v;
}

static void an_raw_exec(const char *sql) {
    char p[128];
    db_path(p, sizeof(p));
    sqlite3 *h = NULL;
    WT_EQ(sqlite3_open(p, &h), SQLITE_OK);
    WT_EQ(sqlite3_exec(h, sql, NULL, NULL, NULL), SQLITE_OK);
    sqlite3_close(h);
    chmod(p, 0600);
}

/* One hour row of host.conns for key at hour h. */
static void hour_row(const char *key, long long h) {
    row(WEB_TIER_HOUR, WM_HOST_CONNS, key, h, 50, 10, 5);
}

/* The audit's case: a baseline of two, a pair evicted and fed again in
 * the same hour. Its old row is deleted before its new one is written,
 * so the write neither fails nor has to take the old row over, and the
 * file holds exactly what memory does. Seen red with the writes put
 * back before the deletes in persist_baseline() (a row taken over:
 * store_baseline_rows_reused 1; with the take-over also removed, the
 * whole batch rolled back: persist_errors 1). */
static void test_baseline_evicted_and_back_in_one_hour(void) {
    fx(1, NULL);
    web_anomaly_destroy(&an);
    web_baseline_destroy(&bl);
    WT_EQ(web_baseline_init(&bl, 2), 0);
    g_cfg.bl = &bl;
    WT_EQ(web_anomaly_init(&an, 32, &g_cfg), 0);
    step(T0);
    hour_row("10.0.0.1", T0);
    hour_row("10.0.0.2", T0);
    step(T0 + HOUR);
    WT_EQ(an_raw_int("SELECT COUNT(*) FROM baseline"), 2);
    hour_row("10.0.0.3", T0 + HOUR);
    hour_row("10.0.0.4", T0 + HOUR);
    hour_row("10.0.0.1", T0 + HOUR);
    step(T0 + 2 * HOUR);
    WT_EQ(web_baseline_evictions(&bl), 3UL);
    WT_EQ(an.st.persist_errors, 0UL);
    web_store_stats_t ss;
    web_store_stats(&st, &ss);
    WT_EQ(ss.bl_rows_reused, 0UL);
    WT_EQ(an_raw_int("SELECT COUNT(*) FROM baseline"), 2);
    WT_EQ(an_raw_int("SELECT COUNT(*) FROM baseline_cell"), 2);
    WT_EQ(an_raw_int("SELECT COUNT(*) FROM baseline WHERE key IN"
                     " ('10.0.0.1','10.0.0.4')"), 2);
    fx_done();
}

/* A batch the store refuses (here: its table gone for an hour) is kept
 * dirty, not lost, and written the hour after. Seen red with
 * web_baseline_redirty() not called (the first hour's cell never
 * reached the file). */
static void test_baseline_refused_batch_is_written_later(void) {
    fx(1, NULL);
    step(T0);
    an_raw_exec("DROP TABLE baseline_cell");
    hour_row("10.0.0.1", T0);
    step(T0 + HOUR);
    WT_ASSERT(an.st.persist_errors >= 1);
    an_raw_exec("CREATE TABLE baseline_cell (cell INTEGER NOT NULL,"
                " id INTEGER NOT NULL, mean REAL NOT NULL, var REAL NOT NULL,"
                " n INTEGER NOT NULL, wvar REAL NOT NULL DEFAULT 0,"
                " wn INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (cell, id))"
                " WITHOUT ROWID");
    hour_row("10.0.0.1", T0 + HOUR);
    step(T0 + 2 * HOUR);
    WT_EQ(an_raw_int("SELECT COUNT(*) FROM baseline WHERE key='10.0.0.1'"), 1);
    WT_EQ(an_raw_int("SELECT COUNT(*) FROM baseline_cell"), 2);
    fx_done();
}

/* Values read back from slothweb.db are checked before they are used:
 * a score past 100 is 100 (the listing rounds it to an integer, which
 * is undefined behaviour for 1e300), and an id of 0 or a time before
 * 1970 is not an episode of ours. The restored episode's own score is
 * read, not only the listing's, which clamps again. A metric below -1
 * cannot come out of the store's reader (it maps a name to -1 or a
 * metric), so it goes to the restore directly. Seen red with the clamp
 * removed from restore_ep() (score 250 in the episode; the listing
 * stayed 100), separately with the id and time checks removed (the
 * other two listed), and with the metric test's lower bound removed
 * (the episode with metric -2 restored). */
static void test_restored_episode_values_are_checked(void) {
    fx(1, NULL);
    web_store_ep_t e[3];
    memset(e, 0, sizeof(e));
    for (int i = 0; i < 3; i++) {
        e[i].id = 10 + i;
        snprintf(e[i].kind, sizeof(e[i].kind), "A6");
        e[i].metric = -1;
        snprintf(e[i].key, sizeof(e[i].key), "10.0.0.%d", 30 + i);
        e[i].state = WEB_EP_OPEN;
        e[i].score = e[i].peak = 40;
        e[i].first_seen = e[i].last_seen = e[i].last_bucket = T0;
    }
    e[0].score = 250;
    e[0].peak = 1e300;
    e[1].id = 0;
    e[2].first_seen = -5;
    WT_EQ(web_store_ep_put(&st, e, 3), 0);
    restart(T0 + 60);
    const char *j = list(T0 + 60);
    WT_HAS(j, "\"key\":\"10.0.0.30\",\"score\":100,\"peak\":100,");
    WT_LACKS(j, "10.0.0.31");
    WT_LACKS(j, "10.0.0.32");
    web_anom_ep_t *r = ep(WEB_ANOM_A6_NAMES, "10.0.0.30");
    WT_EQ(r->state, WEB_EP_OPEN);
    WT_ASSERT(r->score == 100.0);
    WT_ASSERT(r->peak == 100.0);
    web_store_ep_t d = e[2];
    d.first_seen = T0;
    d.id = 20;
    d.metric = -2;
    snprintf(d.key, sizeof(d.key), "10.0.0.34");
    web_anomaly_restore_episode(&an, &d);
    WT_EQ(ep(WEB_ANOM_A6_NAMES, "10.0.0.34")->state, WEB_EP_FREE);
    d.id = 21;
    d.metric = -1;
    snprintf(d.key, sizeof(d.key), "10.0.0.35");
    web_anomaly_restore_episode(&an, &d);
    WT_EQ(ep(WEB_ANOM_A6_NAMES, "10.0.0.35")->state, WEB_EP_OPEN);
    fx_done();
}
#endif

/* A zone half an hour off UTC (IST, +5:30). A device present every day
 * from 13:30 to 14:30 local is present in the UTC hour bucket 08:00Z,
 * filed under cell 13; at 14:10 local it must be scored against that
 * cell, not against cell 14 (the bucket 09:00Z, 14:30-15:30, where it
 * is absent). Seen red with web_baseline_score() taking the cell of t
 * itself (A3 fired on a perfectly regular routine). */
static void test_a3_half_hour_zone_scores_its_own_bucket(void) {
    setenv("TZ", "IST-5:30", 1);
    tzset();
    fx(0, NULL);
    long long h = THU0 + 8 * HOUR;
    /* Four weeks of the routine, in time order: present in 08:00Z,
     * absent in 09:00Z. */
    for (int k = 4; k >= 1; k--) {
        web_baseline_feed(&bl, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:05",
                          h - k * WEEK, 1, 1);
        web_baseline_feed(&bl, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:05",
                          h + HOUR - k * WEEK, 0, 0);
    }
    web_bl_cell_t c[WEB_BL_CELLS];
    WT_EQ(web_baseline_cells(&bl, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:05", c), 0);
    WT_ASSERT(c[web_bl_cell_index(h)].n == 4 && c[web_bl_cell_index(h)].mean == 1);
    WT_ASSERT(c[web_bl_cell_index(h + HOUR)].n == 4 &&
              c[web_bl_cell_index(h + HOUR)].mean == 0);
    /* 14:10 local is in local hour 14, the absent cell. */
    WT_EQ(web_bl_cell_index(h + 40 * 60), web_bl_cell_index(h + HOUR));
    step(h + 40 * 60);
    row(WEB_TIER_MINUTE, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:05", h + 40 * 60,
        1, 1, 1);
    step(h + 41 * 60);
    WT_EQ(count_rule(WEB_ANOM_A3_HOURS), 0);
    fx_done();
    setenv("TZ", "UTC0", 1);
    tzset();
}

/* ── A10 ─────────────────────────────────────────────────────────────── */

/* Connected and never a record: fires once the limit has passed since
 * the connection. The previous slice skipped it (age -1). */
static void test_a10_fires_when_a_connection_never_sends(void) {
    web_live_t live;
    web_live_init(&live, "unix:/test/sloth.sock");
    web_live_sock_connected(&live, 0);
    fx(0, &live);
    step(T0);
    g_mono = (WEB_ANOM_A10_SILENCE_S + 5) * 1000LL;
    step(T0 + 60);
    WT_ASSERT(ep(WEB_ANOM_A10_SENSOR, "")->state != WEB_EP_FREE);
    WT_HAS(list(T0 + 60), "\"kind\":\"sensor\"");
    fx_done();
    web_live_destroy(&live);
}

/* A reconnect after a long outage is not silence: half a second in, the
 * fresh connection has not had its chance to send. Seen red with the
 * silence counted from the last record alone (299 s). */
static void test_a10_silent_just_after_a_reconnect(void) {
    web_live_t live;
    web_feed_t feedr;
    web_live_init(&live, "unix:/test/sloth.sock");
    web_live_sock_connected(&live, 0);
    web_feed_reset(&feedr);
    const char rec[] = "{\"type\":\"device\",\"count\":1}\n";
    web_feed_bytes(&feedr, &live, rec, strlen(rec), 1000);
    web_live_sock_failed(&live, "gone", 250, 2000);
    web_live_sock_connected(&live, 300000);
    fx(0, &live);
    g_mono = 300000;
    step(T0);
    g_mono = 300500;
    step(T0 + 60);
    WT_EQ(count_rule(WEB_ANOM_A10_SENSOR), 0);
    fx_done();
    web_live_destroy(&live);
}

/* A disconnected socket is not a silent sensor. Two guards hold it (the
 * silence is -1 while not connected, and the check asks for a
 * connection), so it was seen red with both relaxed together. */
static void test_a10_silent_while_disconnected(void) {
    web_live_t live;
    web_feed_t feedr;
    web_live_init(&live, "unix:/test/sloth.sock");
    web_live_sock_connected(&live, 0);
    web_feed_reset(&feedr);
    const char rec[] = "{\"type\":\"device\",\"count\":1}\n";
    web_feed_bytes(&feedr, &live, rec, strlen(rec), 1000);
    web_live_sock_failed(&live, "gone", 250, 2000);
    fx(0, &live);
    step(T0);
    g_mono = 600000;
    step(T0 + 60);
    WT_EQ(count_rule(WEB_ANOM_A10_SENSOR), 0);
    fx_done();
    web_live_destroy(&live);
}

/* Inside the limit: silent. Seen red with the limit dropped to 0. */
static void test_a10_silent_before_the_limit(void) {
    web_live_t live;
    web_feed_t feedr;
    web_live_init(&live, "unix:/test/sloth.sock");
    web_live_sock_connected(&live, 0);
    web_feed_reset(&feedr);
    const char rec[] = "{\"type\":\"device\",\"count\":1}\n";
    web_feed_bytes(&feedr, &live, rec, strlen(rec), 1000);
    fx(0, &live);
    g_mono = 1000;
    step(T0);
    g_mono = 6000;
    step(T0 + 60);
    WT_EQ(count_rule(WEB_ANOM_A10_SENSOR), 0);
    fx_done();
    web_live_destroy(&live);
}

/* Without a store: z alone for a counter (no MAD), no A9, nothing
 * persisted, and the rest still runs. The MAD absence was seen red in
 * the WITH_SQLITE=0 build (a lookup counted) with the store test
 * removed from mad_confirms(); the A9 one, as a crash on the NULL store,
 * with it removed from minute_pass()'s A9 call. */
static void test_memory_only_engine(void) {
    fx(0, NULL);
    WT_EQ(web_anomaly_restore(&an, T0), 0);
    const double v[] = { 6, 6, 6 };
    seed(WM_DNS_QUERIES, "10.0.0.9", T0, v, 3);
    step(T0);
    for (int i = 0; i < 3; i++) {
        counter(WM_DNS_QUERIES, "10.0.0.9", T0 + i * 60, 60);
        counter(WM_FLOW_SSH, "10.0.0.80", T0 + i * 60, 1);
        step(T0 + (i + 1) * 60);
    }
    WT_ASSERT(ep(WEB_ANOM_A1_RATE, "10.0.0.9")->state == WEB_EP_OPEN);
    WT_LACKS(ep(WEB_ANOM_A1_RATE, "10.0.0.9")->evidence, "mad_z");
    WT_EQ(an.st.mad_queries, 0UL);
    WT_EQ(count_rule(WEB_ANOM_A9_PROTO), 0);
    WT_EQ(an.st.persist_errors, 0UL);
    fx_done();
}

/* ── M4 (#162): A4, A2's durable first_seen, |z| now ─────────────────── */

static oui_build_t g_oui4;

/* The engine again with M4's inputs: an OUI table, a sloth.db. */
static void engine_m4(const web_oui_tab_t *oui, web_slothdb_t *sdb) {
    web_anomaly_destroy(&an);
    web_baseline_destroy(&bl);
    g_cfg.oui = oui;
    g_cfg.sdb = sdb;
    engine();
}

static void present(const char *mac, long long t) {
    row(WEB_TIER_MINUTE, WM_DEV_PRESENT, mac, t, 1, 1, 1);
}

/* A present MAC whose OUI is in no IEEE block is A4's, while it stays;
 * Apple's OUI, a locally administered MAC and a group address are not.
 * Seen red with a4_check()'s local/multicast test removed (the LA MAC
 * opened an episode) and with web_oui_lookup()'s result ignored (every
 * MAC did). */
static void test_a4_unknown_vendor(void) {
    fx(0, NULL);
    WT_EQ(sdb_oui(&g_oui4, g_dir), 0);
    engine_m4(&g_oui4.tab, NULL);
    WT_ASSERT(web_anomaly_a4_reason(&an) == NULL);
    step(T0);
    for (int m = 0; m < 3; m++) {
        present("a8:00:00:00:00:01", T0 + m * 60);
        present("00:03:93:00:00:02", T0 + m * 60);
        present("02:00:00:00:00:03", T0 + m * 60);
        present("01:00:5e:00:00:04", T0 + m * 60);
        step(T0 + (m + 1) * 60);
    }
    web_anom_ep_t *e = ep(WEB_ANOM_A4_VENDOR, "a8:00:00:00:00:01");
    WT_ASSERT(e->state == WEB_EP_OPEN);
    WT_EQ(count_rule(WEB_ANOM_A4_VENDOR), 1);
    const char *j = list(T0 + 180);
    WT_HAS(j, "\"rule\":\"A4\",\"kind\":\"vendor\"");
    WT_HAS(j, "a8:00:00:00:00:01 present; its OUI a8:00:00 is in no IEEE");
    WT_EQ(an.st.a4_checked, 12UL);
    WT_EQ(an.st.a4_unknown, 3UL);
    /* Gone two minutes: closed, as A3's presence episodes close. */
    step(T0 + 240);
    step(T0 + 300);
    WT_ASSERT(e->state == WEB_EP_CLOSED);
    /* The kind filter and the per-key readers. */
    WT_EQ(web_anomaly_key_count(&an, "a8:00:00:00:00:01", -1), 1);
    WT_EQ(web_anomaly_key_count(&an, "a8:00:00:00:00:01",
                                web_anomaly_kind_find("vendor")), 1);
    WT_EQ(web_anomaly_key_count(&an, "a8:00:00:00:00:01",
                                web_anomaly_kind_find("rate")), 0);
    web_anom_ep_t one[2];
    WT_EQ(web_anomaly_key_list(&an, "a8:00:00:00:00:01", one, 2), 1);
    oui_build_free(&g_oui4);
    fx_done();
}

/* With only sloth's own table (no oui.csv at build time) A4 is off and
 * says why: a miss in 117 entries is not an unknown vendor. Seen red
 * with web_anomaly_a4_reason() returning NULL for any table (a8:..
 * and every other OUI sloth lacks opened). */
static void test_a4_off_without_the_ieee_table(void) {
    fx(0, NULL);
    oui_build_t sl;
    oui_build_init(&sl);
    WT_EQ(oui_build_sloth(&sl, "src/oui.c"), 0);
    WT_EQ(oui_build_finish(&sl, "sloth"), 0);
    engine_m4(&sl.tab, NULL);
    WT_ASSERT(web_anomaly_a4_reason(&an) != NULL);
    WT_HAS(web_anomaly_a4_reason(&an), "not the IEEE registry");
    step(T0);
    present("a8:00:00:00:00:01", T0);
    step(T0 + 60);
    WT_EQ(count_rule(WEB_ANOM_A4_VENDOR), 0);
    WT_EQ(an.st.a4_checked, 0UL);
    engine_m4(NULL, NULL);
    WT_HAS(web_anomaly_a4_reason(&an), "no vendor table");
    oui_build_free(&sl);
    fx_done();
}

/* Made-up OUIs in a burst are one episode keyed "", not one each.
 * Seen red with WEB_ANOM_A4_BURST raised to 64 (ten episodes). */
static void test_a4_burst_is_one_episode(void) {
    fx(0, NULL);
    WT_EQ(sdb_oui(&g_oui4, g_dir), 0);
    engine_m4(&g_oui4.tab, NULL);
    step(T0);
    for (int i = 0; i < 10; i++) {
        char mac[24];
        snprintf(mac, sizeof(mac), "a8:00:%02x:00:00:01", i);
        present(mac, T0);
    }
    step(T0 + 60);
    WT_EQ(count_rule(WEB_ANOM_A4_VENDOR), 1);
    WT_ASSERT(ep(WEB_ANOM_A4_VENDOR, "")->state == WEB_EP_OPEN);
    WT_HAS(list(T0 + 60), "10 present MACs with an OUI in no IEEE block");
    oui_build_free(&g_oui4);
    fx_done();
}

/* The device |z| the Devices table shows: A1's latest score of a device
 * key's metric, fresh for WEB_ANOM_Z_FRESH_S; a host key's is not a
 * device's. Seen red with z_note() not called (no z). */
static void test_device_z_now(void) {
    fx(0, NULL);
    seed(WM_DEV_FRAMES, "00:11:22:33:44:55", T0, FIVE3, 3);
    seed(WM_HOST_CONNS, "10.0.0.5", T0, FIVE3, 3);
    step(T0);
    counter(WM_DEV_FRAMES, "00:11:22:33:44:55", T0, 50);
    gauge(WM_HOST_CONNS, "10.0.0.5", T0, 500);
    step(T0 + 60);
    double z = 0;
    WT_EQ(web_anomaly_device_z(&an, "00:11:22:33:44:55", T0 + 60, &z), 1);
    WT_ASSERT(z > 3);
    WT_EQ(web_anomaly_device_z(&an, "10.0.0.5", T0 + 60, &z), 0);
    WT_EQ(web_anomaly_device_z(&an, "00:11:22:33:44:55",
                               T0 + 60 + WEB_ANOM_Z_FRESH_S + 61, &z), 0);
    fx_done();
}

#ifdef WITH_SQLITE
/* A2 with sloth.db: devices.first_seen, which sloth keeps as MIN()
 * across its own restarts, outlives the stream's. A MAC sloth.db has
 * known for a month is not new whatever the stream says (and with no
 * sloth.db it would be: the same stream, the same engine, reported);
 * one it first saw two hours ago is; one only sloth.db names (a wired
 * device: no first_seen on the stream) is too; a randomised one never.
 * Seen red with a2_sdb_old() returning 0 (the month-old MAC reported),
 * with a2_sdb_firsts() not called (the wired MAC not), and with its
 * locally-administered test removed (the randomised MAC reported). */
static void test_a2_durable_first_seen(void) {
    fx(1, NULL);
    char p[128];
    snprintf(p, sizeof(p), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(p, db_schema_version(), 1), 0);
    char sql[1024];
    snprintf(sql, sizeof(sql),
             "INSERT INTO devices (mac,first_seen,last_seen) VALUES"
             " ('00:11:22:33:44:77',%lld,%lld),('00:11:22:33:44:78',%lld,%lld),"
             " ('00:11:22:33:44:79',%lld,%lld),('02:11:22:33:44:7a',%lld,%lld);",
             T0 - 30 * 86400, T0, T0 - 2 * HOUR, T0, T0 - 3 * HOUR, T0,
             T0 - HOUR, T0);
    WT_EQ(sdb_exec(p, sql), 0);
    web_slothdb_t sdb;
    web_slothdb_init(&sdb, p, NULL);
    engine_m4(NULL, &sdb);
    step(T0);
    probe("00:11:22:33:44:77", T0 - 60, T0);
    probe("00:11:22:33:44:78", T0 - 2 * HOUR, T0);
    step(T0 + 60);
    WT_EQ(ep(WEB_ANOM_A2_NEW, "00:11:22:33:44:77")->state, WEB_EP_FREE);
    WT_EQ(ep(WEB_ANOM_A2_NEW, "00:11:22:33:44:78")->state, WEB_EP_OPEN);
    WT_EQ(ep(WEB_ANOM_A2_NEW, "00:11:22:33:44:79")->state, WEB_EP_OPEN);
    WT_EQ(ep(WEB_ANOM_A2_NEW, "02:11:22:33:44:7a")->state, WEB_EP_FREE);
    WT_HAS(list(T0 + 60), "00:11:22:33:44:79 first seen by sloth 181 min ago "
                          "(sloth.db)");
    WT_ASSERT(an.st.a2_sdb_old >= 1);
    WT_EQ(an.st.a2_sdb_new, 1UL);
    WT_EQ(an.st.a2_sdb_errors, 0UL);
    /* sloth.db read-only throughout: no side file appeared. */
    char l[512];
    sdb_listing(g_dir, l, sizeof(l));
    WT_LACKS(l, "sloth.db-wal");
    WT_LACKS(l, "sloth.db-shm");
    /* The same stream with no sloth.db: the month-old MAC is new. */
    engine_m4(NULL, NULL);
    step(T0 + 60);
    probe("00:11:22:33:44:77", T0 - 60, T0 + 60);
    step(T0 + 120);
    WT_EQ(ep(WEB_ANOM_A2_NEW, "00:11:22:33:44:77")->state, WEB_EP_OPEN);
    /* A sloth.db that is not there: the stream path, and the error is
     * the reader's to report, not A2's. */
    web_slothdb_t gone;
    char q[160];
    snprintf(q, sizeof(q), "%s/absent.db", g_dir);
    web_slothdb_init(&gone, q, NULL);
    engine_m4(NULL, &gone);
    step(T0 + 120);
    probe("00:11:22:33:44:88", T0 - 60, T0 + 120);
    step(T0 + 180);
    WT_EQ(ep(WEB_ANOM_A2_NEW, "00:11:22:33:44:88")->state, WEB_EP_OPEN);
    web_anomaly_destroy(&an);
    web_baseline_destroy(&bl);
    g_cfg.sdb = NULL;
    engine();
    web_slothdb_destroy(&gone);
    web_slothdb_destroy(&sdb);
    unlink(p);
    fx_done();
}
#endif

void run_anomaly_tests(void) {
    WT_RUN(test_a1_fires_on_sustained_burst);
    WT_RUN(test_a1_two_minutes_never_open);
    WT_RUN(test_a1_gauge_gap_breaks_streak);
    WT_RUN(test_a1_quiet_jitter_fires_nothing);
    WT_RUN(test_a1_silent_counter_scores_zero);
    WT_RUN(test_a1_unobserved_minutes_are_not_scored);
    WT_RUN(test_a1_bucket_in_two_parts_is_one_bucket);
    WT_RUN(test_a1_scores_every_key);
    WT_RUN(test_episode_closes_after_two_quiet_minutes);
    WT_RUN(test_closed_episode_listed_for_its_window);
    WT_RUN(test_reopen_needs_a_fresh_streak);
    WT_RUN(test_full_table_keeps_open_episodes);
    WT_RUN(test_worst_case_listing_fits);
    WT_RUN(test_listing_filters);
    WT_RUN(test_changes_feed);
    WT_RUN(test_changes_returns_the_newest_max);
    WT_RUN(test_hour_pass_learns_the_within_hour_spread);
    WT_RUN(test_a2_new_device_reported_once);
    WT_RUN(test_a2_not_new_after_sloth_restarts);
#ifdef WITH_SQLITE
    WT_RUN(test_a2_not_new_by_the_stores_rows);
#endif
    WT_RUN(test_a2_flood_is_one_episode_and_keeps_history);
    WT_RUN(test_slot_policy_keeps_each_rules_history);
    WT_RUN(test_a2_reported_set_evicts_oldest);
    WT_RUN(test_a2_full_table_delays_not_loses);
    WT_RUN(test_a2_rereports_bounded_by_evictions);
    WT_RUN(test_a2_burst_evidence_counts_exactly);
    WT_RUN(test_a2_trickle_is_one_episode);
    WT_RUN(test_a2_scans_every_identity_slot);
    WT_RUN(test_a2_old_and_random_macs_are_not_new);
    WT_RUN(test_a3_fires_for_off_hours_presence);
    WT_RUN(test_a3_needs_four_weeks);
    WT_RUN(test_a3_silent_in_normal_hours);
    WT_RUN(test_a5_random_mac_with_anothers_name);
    WT_RUN(test_a5_reassigned_lease_names_one_mac);
    WT_RUN(test_a6_name_disagreement);
    WT_RUN(test_a6_evidence_is_escaped);
    WT_RUN(test_a7_fires_far_above_its_p95);
    WT_RUN(test_a7_silent_without_history_or_margin);
    WT_RUN(test_a7_silent_below_the_min_excess);
    WT_RUN(test_a3_half_hour_zone_scores_its_own_bucket);
    WT_RUN(test_a8_fires_for_the_client);
    WT_RUN(test_a8_needs_twenty_queries_and_the_share);
#ifdef WITH_SQLITE
    WT_RUN(test_a9_first_use);
    WT_RUN(test_a9_silent_for_history_across_restart);
    WT_RUN(test_mad_refutes_a_return_to_normal);
    WT_RUN(test_mad_confirms_a_real_burst);
    WT_RUN(test_mad_counts_the_within_hour_spread);
    WT_RUN(test_state_survives_restart);
    WT_RUN(test_a7_history_survives_restart);
    WT_RUN(test_baseline_evicted_and_back_in_one_hour);
    WT_RUN(test_baseline_refused_batch_is_written_later);
    WT_RUN(test_restored_episode_values_are_checked);
#endif
    WT_RUN(test_a10_fires_when_a_connection_never_sends);
    WT_RUN(test_a10_silent_just_after_a_reconnect);
    WT_RUN(test_a10_silent_while_disconnected);
    WT_RUN(test_a10_silent_before_the_limit);
    WT_RUN(test_memory_only_engine);
    WT_RUN(test_a4_unknown_vendor);
    WT_RUN(test_a4_off_without_the_ieee_table);
    WT_RUN(test_a4_burst_is_one_episode);
    WT_RUN(test_device_z_now);
#ifdef WITH_SQLITE
    WT_RUN(test_a2_durable_first_seen);
#endif
}
