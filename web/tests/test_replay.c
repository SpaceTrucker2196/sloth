/* M3's acceptance (#161, docs/web-ui-spec.md §12): a JSONL stream
 * generated here, in memory, never a committed fixture, replayed at
 * speed through everything production runs between the data socket and
 * /api/anomalies: the line framer and decoder (web_feed_bytes), the live
 * state, the metric derivation, the identity tables, the rollup, the
 * store thread's step (web_tsdb_step) with its flush and its rows hook,
 * the baselines, the rules and the episode table, wired by
 * web_anomaly_attach() exactly as main.c wires them. Only the clocks are
 * pinned: wall seconds for the rollup and the rules, a matching
 * monotonic one for the live state.
 *
 * A 7 d stream cannot warm a cell on its own: a cell sees one sample a
 * week, warms at three (§5.3) and A3 needs four. So the generated
 * stream is six weeks: four of routine, then the quiet 7 d acceptance
 * week (the same routine, jitter and all), then the 7 d week with the
 * two events: a burst of connections (A1) and a daytime device that, in
 * that week, appears only at night (A3). A device that is only ever
 * present at night is in every week and must never fire.
 *
 * It runs in both builds: without SQLite the rows reach the engine off
 * the rollup's queue all the same. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "web_anomaly.h"
#include "web_baseline.h"
#include "web_ident.h"
#include "web_ingest.h"
#include "web_live.h"
#include "web_metrics.h"
#include "web_rollup.h"
#include "web_store.h"
#include "web_tsdb.h"
#include "wtest.h"

#define HOUR  3600LL
#define DAY   86400LL
#define WEEK  (7 * DAY)
#define START 1792368000LL               /* Monday 2026-10-19 00:00 UTC */

static long long g_now;
static long long wall_fn(void *c) { (void)c; return g_now; }
static long long mono_fn(void *c) { (void)c; return (g_now - START) * 1000 + 1000; }

typedef struct {
    char           dir[64];
    web_store_t    st;
    int            have_st;
    web_rollup_t   ru;
    web_metrics_t  mx;
    web_ident_t    idt;
    web_live_t     live;
    web_feed_t     feed;
    web_tsdb_t     ts;
    web_baseline_t bl;
    web_anomaly_t  an;
} rig_t;

static rig_t R;

static void rig_up(void) {
    memset(&R, 0, sizeof(R));
    snprintf(R.dir, sizeof(R.dir), "/tmp/slothweb-replay-XXXXXX");
    WT_ASSERT(mkdtemp(R.dir) != NULL);
    char p[128], err[512];
    snprintf(p, sizeof(p), "%s/r.db", R.dir);
    if (web_store_available()) {
        WT_EQ(web_store_open(&R.st, p, err, sizeof(err)), 0);
        R.have_st = 1;
    }
    g_now = START;
    WT_EQ(web_rollup_init(&R.ru, 64, R.have_st ? 1 : WEB_ROLLUP_Q_LONG, err,
                          sizeof(err)), 0);
    WT_EQ(web_metrics_init(&R.mx, &R.ru, wall_fn, NULL), 0);
    WT_EQ(web_ident_init(&R.idt, 64, 32), 0);
    web_metrics_set_ident(&R.mx, &R.idt);
    web_live_init(&R.live, "unix:/test/sloth.sock");
    web_live_sock_connected(&R.live, mono_fn(NULL));
    web_feed_reset(&R.feed);
    R.feed.metrics = &R.mx;
    WT_EQ(web_tsdb_init(&R.ts, &R.ru, R.have_st ? &R.st : NULL, 30, 256,
                        wall_fn, NULL), 0);
    WT_EQ(web_baseline_init(&R.bl, web_baseline_cap_for(64)), 0);
    web_anom_cfg_t c = { &R.bl, R.have_st ? &R.st : NULL, &R.live, &R.idt,
                         mono_fn, NULL, 64 };
    WT_EQ(web_anomaly_init(&R.an, WEB_ANOM_CAP, &c), 0);
    WT_EQ(web_anomaly_restore(&R.an, g_now), 0);
    web_anomaly_attach(&R.an, &R.ts);
}

static void rig_down(void) {
    web_tsdb_flush_all(&R.ts);
    web_anomaly_destroy(&R.an);
    web_baseline_destroy(&R.bl);
    web_tsdb_destroy(&R.ts);
    web_metrics_destroy(&R.mx);
    web_ident_destroy(&R.idt);
    web_rollup_destroy(&R.ru);
    web_live_destroy(&R.live);
    if (R.have_st) web_store_close(&R.st);
    char p[128], s[160];
    snprintf(p, sizeof(p), "%s/r.db", R.dir);
    unlink(p);
    snprintf(s, sizeof(s), "%s-wal", p); unlink(s);
    snprintf(s, sizeof(s), "%s-shm", p); unlink(s);
    rmdir(R.dir);
}

/* A small deterministic generator, so the jitter is the same on every
 * run and every host. */
static unsigned g_rng = 12345;
static int jit(int span) {
    g_rng = g_rng * 1103515245u + 12345u;
    return (int)((g_rng >> 16) % (unsigned)(2 * span + 1)) - span;
}

#define MAC_DAY   "00:16:3e:00:00:01"
#define MAC_NIGHT "00:16:3e:00:00:02"
#define MAC_X     "00:16:3e:00:00:03"

typedef struct {
    int burst;        /* week 6's events on */
} plan_t;

static int hour_of(long long t) { return (int)((t % DAY) / HOUR); }

/* Who is present at t. X keeps office hours until the event week, in
 * which it appears only between 02:00 and 03:00. */
static int present(const char *mac, long long t, const plan_t *pl) {
    int h = hour_of(t);
    if (!strcmp(mac, MAC_DAY)) return h >= 8 && h < 18;
    if (!strcmp(mac, MAC_NIGHT)) return h >= 1 && h < 5;
    if (pl->burst) return h == 2;
    return h >= 9 && h < 17;
}

/* One snapshot pass at t, as sloth writes it: interfaces first, the
 * top host, the devices; and the capture thread's DNS. */
static size_t pass(char *b, size_t cap, long long t, const plan_t *pl,
                   int burst_now) {
    size_t o = 0;
    o += (size_t)snprintf(b + o, cap - o,
        "{\"type\":\"iface\",\"ts\":%lld,\"name\":\"eth0\",\"rx_rate\":%d,"
        "\"tx_rate\":%d}\n", t, 50000 + jit(5000), 20000 + jit(2000));
    int conns = burst_now ? 200 : 5 + jit(1);
    o += (size_t)snprintf(b + o, cap - o,
        "{\"type\":\"top_host\",\"ts\":%lld,\"ip\":\"10.0.0.5\",\"hostname\":"
        "\"\",\"first_seen\":%lld,\"last_seen\":%lld,\"conn_count\":%d,"
        "\"rx_rate\":%d,\"tx_rate\":%d}\n", t, START, t, conns,
        8000 + jit(800), 3000 + jit(300));
    static const char *const macs[] = { MAC_DAY, MAC_NIGHT, MAC_X };
    for (int i = 0; i < 3; i++) {
        if (!present(macs[i], t, pl)) continue;
        o += (size_t)snprintf(b + o, cap - o,
            "{\"type\":\"device\",\"ts\":%lld,\"mac\":\"%s\",\"ip\":"
            "\"10.0.1.%d\",\"hostname\":\"\",\"last_seen\":%lld}\n", t,
            macs[i], i + 10, t);
    }
    for (int q = 0; q < 2; q++) {
        o += (size_t)snprintf(b + o, cap - o,
            "{\"type\":\"dns\",\"ts\":%lld,\"src\":\"10.0.0.5\",\"qname\":"
            "\"h%lld-%d.example\",\"qtype\":\"A\",\"answer\":\"\","
            "\"is_resp\":0}\n", t, t, q);
        o += (size_t)snprintf(b + o, cap - o,
            "{\"type\":\"dns\",\"ts\":%lld,\"src\":\"10.0.0.1\",\"qname\":"
            "\"h%lld-%d.example\",\"qtype\":\"A\",\"answer\":\"192.0.2.7\","
            "\"is_resp\":1}\n", t, t, q);
    }
    return o;
}

/* The burst: Tuesday 14:00 to 14:05 of the event week. */
static int burst_at(long long t, long long wk) {
    return t >= wk + DAY + 14 * HOUR && t < wk + DAY + 14 * HOUR + 300;
}

/* Replay [from, to) one pass a minute: the pass's records through the
 * framer at their own second, then the store thread's step. */
static void replay(long long from, long long to, const plan_t *pl, long long wk,
                   void (*check)(long long t)) {
    static char buf[8192];
    for (long long t = from; t < to; t += 60) {
        g_now = t;
        size_t n = pass(buf, sizeof(buf), t, pl, pl->burst && burst_at(t, wk));
        web_feed_bytes(&R.feed, &R.live, buf, n, mono_fn(NULL));
        web_tsdb_step(&R.ts, t);
        if (check) check(t);
    }
}

static const char *listing(long long since) {
    static char body[65536 - 1024];
    size_t n = web_anomaly_json(&R.an, g_now, since, -1, body, sizeof(body));
    WT_ASSERT(n > 0);
    body[n < sizeof(body) ? n : sizeof(body) - 1] = '\0';
    return body;
}

static int seen_a1, seen_a3, seen_a3_night_device, seen_a3_day_device;

static void watch(long long t) {
    (void)t;
    for (int i = 0; i < R.an.cap; i++) {
        const web_anom_ep_t *e = &R.an.ep[i];
        if (e->state != WEB_EP_OPEN) continue;
        if (e->rule == WEB_ANOM_A1_RATE && e->metric == WM_HOST_CONNS &&
            !strcmp(e->key, "10.0.0.5"))
            seen_a1 = 1;
        if (e->rule == WEB_ANOM_A3_HOURS) {
            if (!strcmp(e->key, MAC_X)) seen_a3 = 1;
            if (!strcmp(e->key, MAC_NIGHT)) seen_a3_night_device = 1;
            if (!strcmp(e->key, MAC_DAY)) seen_a3_day_device = 1;
        }
    }
}

static void test_six_weeks_quiet_then_burst_and_night(void) {
    rig_up();
    plan_t routine = { 0 }, events = { 1 };
    long long wk5 = START + 4 * WEEK, wk6 = START + 5 * WEEK;
    replay(START, wk5, &routine, 0, NULL);
    /* The baselines warmed through the real path: X's day cells say
     * present, its night cells absent, over four weeks of samples. */
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&R.bl, WM_DEV_PRESENT, MAC_X, wk5 + 10 * HOUR,
                             1.0, &sc), 0);
    WT_ASSERT(sc.n >= 3 && sc.mean > 0.9);
    WT_EQ(web_baseline_score(&R.bl, WM_DEV_PRESENT, MAC_X, wk5 + 2 * HOUR,
                             1.0, &sc), 0);
    WT_ASSERT(sc.n >= 3 && sc.mean < 0.1);
    WT_EQ(web_baseline_score(&R.bl, WM_HOST_CONNS, "10.0.0.5", wk5 + 14 * HOUR,
                             5.0, &sc), 0);
    WT_ASSERT(!sc.warming);

    /* The quiet acceptance week: nothing at all fires, in it or before
     * it. Seen red with the sd floor removed (host.conns' hour means
     * barely move, so a minute of 4 or 6 scored |z| > 10) and with the
     * zero feeds removed (X's night cells never left warming, so the
     * baseline check above failed). */
    replay(wk5, wk6, &routine, 0, NULL);
    WT_EQ(R.an.st.opened, 0UL);
    WT_HAS(listing(g_now - WEB_ANOM_KEEP_S), "\"anomalies\":[]");
    web_anom_stats_t s;
    web_anomaly_stats(&R.an, &s);
    WT_EQ(s.open + s.closed_kept, 0);
    WT_ASSERT(s.hours_fed >= 5 * 168 - 1);
    WT_EQ(s.hours_unobserved, 0UL);

    /* The event week. */
    replay(wk6, wk6 + WEEK, &events, wk6, watch);
    WT_EQ(seen_a1, 1);
    WT_EQ(seen_a3, 1);
    WT_EQ(seen_a3_night_device, 0);
    WT_EQ(seen_a3_day_device, 0);
    rig_down();
}

/* The audit's race, through the real store thread step: the hour that
 * just closed reaches the baseline whatever the flush phase. The
 * previous slice fed it only when the 10 s flush happened to fall on the
 * hour (start offsets 3 and 7 fed nothing). Driven second by second. */
static void hour_feed_at(int off) {
    rig_up();
    long long h0 = START + HOUR;
    for (long long t = START + off; t < h0 + 3630; t++) {
        char b[256];
        g_now = t;
        int n = snprintf(b, sizeof(b), "{\"type\":\"top_host\",\"ts\":%lld,"
                         "\"ip\":\"10.0.0.9\",\"conn_count\":5}\n", t);
        web_feed_bytes(&R.feed, &R.live, b, (size_t)n, mono_fn(NULL));
        web_tsdb_step(&R.ts, t);
    }
    web_bl_cell_t c[WEB_BL_CELLS];
    WT_EQ(web_baseline_cells(&R.bl, WM_HOST_CONNS, "10.0.0.9", c), 0);
    WT_EQ(c[web_bl_cell_index(h0)].n, 1);
    rig_down();
}

static void test_hour_feed_any_flush_phase(void) {
    hour_feed_at(0);
    hour_feed_at(3);
    hour_feed_at(7);
}

void run_replay_tests(void) {
    WT_RUN(test_hour_feed_any_flush_phase);
    WT_RUN(test_six_weeks_quiet_then_burst_and_night);
}
