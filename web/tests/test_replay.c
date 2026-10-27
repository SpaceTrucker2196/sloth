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
 * week (the same routine, noise and all), then the 7 d week with the
 * two events: a burst of connections (A1) and a daytime device that, in
 * that week, appears only at night (A3). A device that is only ever
 * present at night is in every week and must never fire.
 *
 * The routine gives every M3 rule its input, so that "nothing fires" is
 * a claim about each of them: noisy gauges (each minute's value spread
 * about +-50% around its mean, the same in every hour) and Poisson
 * counts, which is what A1 has to stay quiet on; devices present by
 * hour (A3); DHCP, mDNS and NBNS names that agree (A6) and a randomised
 * MAC with a name of its own (A5); a probe client sloth has known for a
 * month (A2); a host's steady ssh use (A9, whose first use in week one
 * is a real first use and fires once there); DNS queries answered
 * without NXDOMAIN (A8); the conn_count peaks A7 learns. In an SQLite
 * build slothweb and sloth both restart in the middle of the quiet week:
 * the baselines and the reported set come back from slothweb.db, and
 * sloth's probe client comes back with a first_seen of "now", which A2
 * must not call new.
 *
 * It runs in both builds: without SQLite the rows reach the engine off
 * the rollup's queue all the same. */
#include <math.h>
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
#include "wt_tmp.h"

#define HOUR  3600LL
#define DAY   86400LL
#define WEEK  (7 * DAY)
#define START 1792368000LL               /* Monday 2026-10-19 00:00 UTC */

static long long g_now;
static long long wall_fn(void *c) { (void)c; return g_now; }
static long long mono_fn(void *c) { (void)c; return (g_now - START) * 1000 + 1000; }

typedef struct {
    char           dir[TEST_TMP_MAX];
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

/* Everything up, on the store in R.dir (a new one when fresh), as
 * main.c starts it: the store, the rollup, the engine, the restore. */
static void rig_open(int fresh) {
    char dir[TEST_TMP_MAX];
    if (!fresh) memcpy(dir, R.dir, sizeof(dir));
    memset(&R, 0, sizeof(R));
    if (fresh) {
        snprintf(R.dir, sizeof(R.dir), "%s/slothweb-replay-XXXXXX", test_tmpdir());
        WT_ASSERT(mkdtemp(R.dir) != NULL);
    } else {
        memcpy(R.dir, dir, sizeof(dir));
    }
    char p[128], err[512];
    snprintf(p, sizeof(p), "%s/r.db", R.dir);
    if (web_store_available()) {
        WT_EQ(web_store_open(&R.st, p, err, sizeof(err)), 0);
        R.have_st = 1;
    }
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
                         mono_fn, NULL, 64, NULL, NULL, NULL };
    WT_EQ(web_anomaly_init(&R.an, WEB_ANOM_CAP, &c), 0);
    WT_EQ(web_anomaly_restore(&R.an, g_now), 0);
    web_anomaly_attach(&R.an, &R.ts);
}

/* Everything down as main.c stops it (the backlog flushed), the files
 * left where they are. */
static void rig_close(void) {
    web_tsdb_flush_all(&R.ts);
    web_anomaly_destroy(&R.an);
    web_baseline_destroy(&R.bl);
    web_tsdb_destroy(&R.ts);
    web_metrics_destroy(&R.mx);
    web_ident_destroy(&R.idt);
    web_rollup_destroy(&R.ru);
    web_live_destroy(&R.live);
    if (R.have_st) web_store_close(&R.st);
}

static void rig_up(void) {
    g_now = START;
    rig_open(1);
}

static void rig_down(void) {
    rig_close();
    char p[128], s[160];
    snprintf(p, sizeof(p), "%s/r.db", R.dir);
    unlink(p);
    snprintf(s, sizeof(s), "%s-wal", p); unlink(s);
    snprintf(s, sizeof(s), "%s-shm", p); unlink(s);
    rmdir(R.dir);
}

/* A small deterministic generator, so the noise is the same on every
 * run and every host. */
static unsigned g_rng = 12345;
static double unif(void) {
    g_rng = g_rng * 1103515245u + 12345u;
    return (double)((g_rng >> 8) & 0xffffffu) / 16777216.0;
}
static int jit(int span) {
    return (int)(unif() * (2 * span + 1)) - span;
}
/* A Poisson count of mean m (Knuth's method; m is small here). */
static int poisson(double m) {
    double l = exp(-m), p = 1.0;
    int k = 0;
    do { k++; p *= unif(); } while (p > l);
    return k - 1;
}

#define MAC_DAY   "00:16:3e:00:00:01"
#define MAC_NIGHT "00:16:3e:00:00:02"
#define MAC_X     "00:16:3e:00:00:03"
#define MAC_PHONE "da:16:3e:00:00:04"     /* randomised, always about */
#define MAC_PROBE "00:16:3e:00:00:05"     /* a probe client, a month old */
#define SSH_HOST  "10.0.0.5"

typedef struct {
    int       burst;        /* week 6's events on */
    long long sloth_start;  /* sloth's own (re)start: its first_seen */
} plan_t;

static int hour_of(long long t) { return (int)((t % DAY) / HOUR); }

/* Who is present at t. X keeps office hours until the event week, in
 * which it appears only between 02:00 and 03:00. */
static int present(const char *mac, long long t, const plan_t *pl) {
    int h = hour_of(t);
    if (!strcmp(mac, MAC_DAY)) return h >= 8 && h < 18;
    if (!strcmp(mac, MAC_NIGHT)) return h >= 1 && h < 5;
    if (!strcmp(mac, MAC_PHONE)) return 1;
    if (pl->burst) return h == 2;
    return h >= 9 && h < 17;
}

/* gauge noise: v +- 50 %, uniform, the same in every hour. */
static int noisy(int v) { return v + jit(v / 2); }

/* One snapshot pass at t, as sloth writes it: interfaces first, the
 * top host, the devices and the names sloth's tables hold for them, the
 * probe client, the ssh flow; and the capture thread's DNS. */
static size_t pass(char *b, size_t cap, long long t, const plan_t *pl,
                   int burst_now) {
    size_t o = 0;
    o += (size_t)snprintf(b + o, cap - o,
        "{\"type\":\"iface\",\"ts\":%lld,\"name\":\"eth0\",\"rx_rate\":%d,"
        "\"tx_rate\":%d}\n", t, noisy(50000), noisy(20000));
    int conns = burst_now ? 200 : 5 + jit(3);
    o += (size_t)snprintf(b + o, cap - o,
        "{\"type\":\"top_host\",\"ts\":%lld,\"ip\":\"" SSH_HOST "\","
        "\"hostname\":\"\",\"first_seen\":%lld,\"last_seen\":%lld,"
        "\"conn_count\":%d,\"rx_rate\":%d,\"tx_rate\":%d}\n", t, START, t,
        conns, noisy(8000), noisy(3000));
    static const char *const macs[] = { MAC_DAY, MAC_NIGHT, MAC_X, MAC_PHONE };
    static const char *const hosts[] = { "office-pc", "nas", "laptop", "phone-a" };
    for (int i = 0; i < 4; i++) {
        if (!present(macs[i], t, pl)) continue;
        o += (size_t)snprintf(b + o, cap - o,
            "{\"type\":\"device\",\"ts\":%lld,\"mac\":\"%s\",\"ip\":"
            "\"10.0.1.%d\",\"hostname\":\"%s\",\"last_seen\":%lld}\n", t,
            macs[i], i + 10, hosts[i], t);
    }
    /* The office PC's three names, which agree in normal form. */
    if (present(MAC_DAY, t, pl))
        o += (size_t)snprintf(b + o, cap - o,
            "{\"type\":\"dhcp_lease\",\"ts\":%lld,\"ip\":\"10.0.1.10\","
            "\"hostname\":\"office-pc\",\"expire\":0}\n"
            "{\"type\":\"mdns_service\",\"ts\":%lld,\"ip\":\"10.0.1.10\","
            "\"host\":\"Office-PC.local\",\"instance\":\"x\",\"service\":"
            "\"_smb._tcp.local\",\"port\":445,\"last_seen\":%lld}\n"
            "{\"type\":\"nbns_name\",\"ts\":%lld,\"ip\":\"10.0.1.10\","
            "\"name\":\"OFFICE-PC\",\"suffix\":0,\"last_seen\":%lld}\n",
            t, t, t, t, t);
    /* The probe client: known to sloth since sloth_start, counting its
     * frames from there. */
    long long since = pl->sloth_start;
    o += (size_t)snprintf(b + o, cap - o,
        "{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":\"" MAC_PROBE "\","
        "\"first_seen\":%lld,\"last_seen\":%lld,\"frame_count\":%lld}\n", t,
        since, t, (t - since) / 60 * 3);
    /* A steady ssh session's banners, one a minute, from a host that has
     * used ssh since before the stream began. */
    o += (size_t)snprintf(b + o, cap - o,
        "{\"type\":\"ssh_flow\",\"ts\":%lld,\"src_ip\":\"" SSH_HOST "\","
        "\"dst_ip\":\"10.0.0.1\",\"server_port\":22,\"first_seen\":%lld,"
        "\"banner_count\":%lld}\n", t, START - 30 * DAY, (t - START) / 60);
    int nq = poisson(2.0);
    for (int q = 0; q < nq; q++) {
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

/* The quiet week's absence, per rule: the episodes any rule has opened
 * in it, named, so a red run says which. */
static int quiet_opened[WEB_ANOM_RULE_COUNT];
static unsigned long long quiet_seq;

static void quiet_watch(long long t) {
    (void)t;
    for (int i = 0; i < R.an.cap; i++) {
        const web_anom_ep_t *e = &R.an.ep[i];
        if (e->state != WEB_EP_FREE && e->seq > quiet_seq &&
            e->rule >= 0 && e->rule < WEB_ANOM_RULE_COUNT && !quiet_opened[e->rule]) {
            quiet_opened[e->rule] = 1;
            fprintf(stderr, "    quiet week: %s %s[%s]: %s\n",
                    web_anomaly_rule(e->rule),
                    e->metric >= 0 ? web_metric_defs[e->metric].name : "-",
                    e->key, e->evidence);
        }
    }
}

static void test_six_weeks_quiet_then_burst_and_night(void) {
    rig_up();
    plan_t routine = { 0, START - 30 * DAY }, events = { 1, 0 };
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
    /* The minutes' own spread was learnt: conn_count is 2..8 every
     * minute (variance 4), while its hour means barely move. */
    WT_ASSERT(sc.within > 3.0 && sc.within < 5.0);
    WT_ASSERT(sc.sd_hour < 1.01);
    /* Every rule had its input. */
    web_anom_stats_t s;
    web_anomaly_stats(&R.an, &s);
    if (R.have_st) {
        /* The one real event of the warm-up: the ssh host's first use. */
        WT_EQ(s.opened, 1UL);
        WT_ASSERT(s.a9_queries >= 1);
    } else {
        WT_EQ(s.opened, 0UL);
    }
    web_id_stats_t is;
    web_ident_stats(&R.idt, &is);
    WT_ASSERT(is.macs >= 5);

    /* The quiet acceptance week: nothing fires in it, with slothweb and
     * sloth restarting on its Wednesday (an SQLite build: the memory
     * build has nothing to come back from). Seen red, each in its own
     * run: A1 with the within-hour term removed from web_bl_cell_sd()
     * (conn_count's minutes of 8 against an hour sd of 0.3); A2 with
     * a2_old_evidence() answering 0
     * (after the restart the probe client's first_seen is "now"), and
     * separately with its window removed (the reader's since and the age
     * test together); A3 with the zero feeds removed (X's night cells
     * never left warming, so the check above failed); A5 with a5_scan()
     * accepting the MAC itself as the other; A6 with names_agree()
     * comparing raw text; A9 with both its guards removed (the known set
     * and the store's earlier row). */
    quiet_seq = R.an.seq;
    unsigned long opened0 = R.an.st.opened;
    long long mid = wk5 + 2 * DAY;
    replay(wk5, mid, &routine, 0, quiet_watch);
    if (R.have_st) {
        rig_close();
        rig_open(0);
        routine.sloth_start = mid;
        WT_ASSERT(web_baseline_count(&R.bl) > 0);
    }
    replay(mid, wk6, &routine, 0, quiet_watch);
    WT_EQ(R.an.st.opened, R.have_st ? 0UL : opened0);
    for (int r = 0; r < WEB_ANOM_RULE_COUNT; r++) WT_EQ(quiet_opened[r], 0);
    WT_HAS(listing(g_now - WEB_ANOM_KEEP_S), "\"anomalies\":[]");
    web_anomaly_stats(&R.an, &s);
    WT_EQ(s.open + s.closed_kept, 0);
    WT_ASSERT(s.hours_fed >= (R.have_st ? 5 * 24 - 2 : 7 * 24 - 1));
    if (R.have_st) WT_ASSERT(s.a2_not_new >= 1);

    /* The event week. */
    events.sloth_start = routine.sloth_start;
    replay(wk6, wk6 + WEEK, &events, wk6, watch);
    WT_EQ(seen_a1, 1);
    WT_EQ(seen_a3, 1);
    WT_EQ(seen_a3_night_device, 0);
    WT_EQ(seen_a3_day_device, 0);
    rig_down();
}

/* A host new to the stream whose first activity is the protocol, at
 * sloth's real cadence (a record every 10 s, the store thread stepping
 * every second): its first minute row is held until its key is
 * established and reaches the engine after that minute's pass. A9 still
 * fires for it, as it does for a host already established. Seen red
 * with the late row's A9 check removed from web_anomaly_rows() (the new
 * host never fired: by the next minute its row was in the store). */
static void test_a9_fires_for_a_new_host_at_real_cadence(void) {
    if (!web_store_available()) return;
    rig_up();
    plan_t routine = { 0, START - 30 * DAY };
    long long t0 = START + 2 * HOUR;
    replay(START, t0, &routine, 0, NULL);
    unsigned long q0 = R.an.st.a9_queries;
    /* The new host's records fall 5 s into each 10 s, so its key is
     * established (a minute after its first sample) only after the
     * sample that closed its first minute: that row is held, and
     * released late. */
    for (long long t = t0; t < t0 + 600; t++) {
        g_now = t;
        if (t % 5 == 0) {
            char b[512];
            int newh = t % 10 != 0;
            int n = snprintf(b, sizeof(b),
                "{\"type\":\"ssh_flow\",\"ts\":%lld,\"src_ip\":\"%s\","
                "\"dst_ip\":\"10.0.0.1\",\"server_port\":2222,"
                "\"first_seen\":%lld,\"banner_count\":%lld}\n", t,
                newh ? "10.0.0.77" : "10.0.0.5", t0, (t - t0) / 10 + 1);
            web_feed_bytes(&R.feed, &R.live, b, (size_t)n, mono_fn(NULL));
        }
        if (t % 60 == 0) {
            static char buf[8192];
            size_t n = pass(buf, sizeof(buf), t, &routine, 0);
            web_feed_bytes(&R.feed, &R.live, buf, n, mono_fn(NULL));
        }
        web_tsdb_step(&R.ts, t);
    }
    int fresh = 0;
    for (int i = 0; i < R.an.cap; i++) {
        const web_anom_ep_t *e = &R.an.ep[i];
        if (e->state != WEB_EP_FREE && e->rule == WEB_ANOM_A9_PROTO &&
            !strcmp(e->key, "10.0.0.77"))
            fresh++;
    }
    WT_EQ(fresh, 1);
    WT_ASSERT(R.an.st.a9_queries > q0);
    WT_ASSERT(R.an.st.late_rows >= 1);
    rig_down();
}

/* A zone half an hour off UTC (IST, +5:30), five weeks of a device
 * present every day from 13:30 to 14:30 local, which is the UTC hour
 * 08:00Z: a perfectly regular routine, and nothing fires. Seen red with
 * web_baseline_score() taking the cell of the minute itself (14:00-14:30
 * local was scored against the absent 14:30-15:30 bucket, and A3 fired
 * every day of week five). */
static void test_half_hour_zone_routine_is_quiet(void) {
    setenv("TZ", "IST-5:30", 1);
    tzset();
    rig_up();
    static char buf[1024];
    for (long long t = START; t < START + 5 * WEEK; t += 60) {
        g_now = t;
        int h = hour_of(t);
        int n = snprintf(buf, sizeof(buf),
            "{\"type\":\"iface\",\"ts\":%lld,\"name\":\"eth0\",\"rx_rate\":%d,"
            "\"tx_rate\":%d}\n", t, noisy(50000), noisy(20000));
        if (h == 8)
            n += snprintf(buf + n, sizeof(buf) - (size_t)n,
                "{\"type\":\"device\",\"ts\":%lld,\"mac\":\"" MAC_X "\","
                "\"ip\":\"10.0.1.12\",\"hostname\":\"\",\"last_seen\":%lld}\n",
                t, t);
        web_feed_bytes(&R.feed, &R.live, buf, (size_t)n, mono_fn(NULL));
        web_tsdb_step(&R.ts, t);
    }
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&R.bl, WM_DEV_PRESENT, MAC_X,
                             START + 4 * WEEK + 8 * HOUR + 600, 1.0, &sc), 0);
    WT_ASSERT(sc.n >= 4 && sc.mean > 0.9);
    WT_EQ(R.an.st.opened, 0UL);
    rig_down();
    setenv("TZ", "UTC0", 1);
    tzset();
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
    WT_RUN(test_a9_fires_for_a_new_host_at_real_cadence);
    WT_RUN(test_half_hour_zone_routine_is_quiet);
}
