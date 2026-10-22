/* The anomaly engine (#161, M3) driven end to end: a real rollup (for
 * key registration), a real slothweb.db (for the minute and hour
 * tiers the rules read), and web_anomaly_step() itself — the same
 * function the tick thread calls once a second in production.
 *
 * Weeks of baseline history are established by calling
 * web_baseline_feed() directly rather than replaying real time hour by
 * hour: that is the engine's own public feed path (what
 * web_anomaly_step's hourly pass calls after reading a closed hour
 * bucket), and a separate, small test below proves that wiring once.
 * Everything "now" — the minute data a rule actually scores — goes
 * through the real store via web_store_write() and is read back by
 * the rule through web_store_query(), the same call production makes. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "web_anomaly.h"
#include "web_baseline.h"
#include "web_ingest.h"
#include "web_live.h"
#include "web_rollup.h"
#include "web_store.h"
#include "wtest.h"

#ifndef WITH_SQLITE

static void test_no_store_build_skips(void) {
    WT_ASSERT(web_store_available() == 0);
}

void run_anomaly_tests(void) {
    WT_RUN(test_no_store_build_skips);
}

#else

#define HOUR 3600LL
#define WEEK (168LL * HOUR)

static char g_dir[64];
static web_store_t  st;
static web_rollup_t ru;
static web_baseline_t bl;
static web_anomaly_t  an;

static int mkdir_tmp(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/slothweb-anomaly-XXXXXX");
    return mkdtemp(g_dir) ? 0 : -1;
}

static void fresh(void) {
    WT_EQ(mkdir_tmp(), 0);
    char p[128], err[256];
    snprintf(p, sizeof(p), "%s/a.db", g_dir);
    WT_EQ(web_store_open(&st, p, err, sizeof(err)), 0);
    WT_EQ(web_rollup_init(&ru, 64, 1, err, sizeof(err)), 0);
    WT_EQ(web_baseline_init(&bl, 64), 0);
    WT_EQ(web_anomaly_init(&an, 32), 0);
}

static void done(void) {
    char p[128], s[160];
    snprintf(p, sizeof(p), "%s/a.db", g_dir);
    web_store_close(&st);
    unlink(p);
    snprintf(s, sizeof(s), "%s-wal", p); unlink(s);
    snprintf(s, sizeof(s), "%s-shm", p); unlink(s);
    rmdir(g_dir);
    web_rollup_destroy(&ru);
    web_baseline_destroy(&bl);
    web_anomaly_destroy(&an);
}

static void seed(int tier, int metric, const char *key, long long t,
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

/* The hour fed into hour-of-week cell idx, WEB_BL_WARM_N+extra times
 * across consecutive weeks starting at t0, value v each time. Returns
 * the last fed hour-start, so a caller can continue the sequence into
 * "now". */
static long long warm(int metric, const char *key, long long t0, double v,
                     int weeks) {
    long long t = t0;
    for (int i = 0; i < weeks; i++) {
        web_baseline_feed(&bl, metric, key, t, v);
        t += WEEK;
    }
    return t - WEEK;
}

/* now_s=0 so the "closed more than WEB_ANOM_RECENT_S ago" filter never
 * trips against the large real-looking timestamps the tests use. */
static const char *anomalies(void) {
    static char body[16384];
    size_t n = web_anomaly_json(&an, 0, body, sizeof(body));
    WT_ASSERT(n > 0);
    body[n] = '\0';
    return body;
}

/* Proves the only piece web_baseline_feed() itself does not cover:
 * web_anomaly_step()'s hourly pass reads the closed hour bucket from
 * the store and calls web_baseline_feed() with it. Mutating the hour
 * boundary math (closed_start) to read the bucket starting at `hour`
 * rather than `hour - 1` would read the *open* bucket instead, which
 * this single seeded row is not there, so the feed would not happen
 * and the probe below would come back warming — caught here. */
static void test_hour_feed_wires_to_baseline(void) {
    fresh();
    long long hour0 = 1792627200; /* an hour boundary */
    seed(WEB_TIER_HOUR, WM_HOST_RX, "10.0.0.9", hour0, 7.0);
    web_rollup_add(&ru, WM_HOST_RX, "10.0.0.9", 7.0, hour0 + 1);
    web_anomaly_step(&an, &bl, &ru, &st, NULL, hour0 + HOUR + 1, 0);
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&bl, WM_HOST_RX, "10.0.0.9", hour0, 7.0, &sc),
         0);
    WT_EQ(sc.n, 1);
    done();
}

/* A1: a quiet host.conns baseline, then three consecutive minutes of
 * a huge burst opens a "rate" episode; the acceptance case from #161's
 * body ("fires A1 for a synthetic burst"). */
static void test_a1_fires_on_sustained_burst(void) {
    fresh();
    long long t0 = 1792627200;
    long long last = warm(WM_HOST_CONNS, "10.0.0.5", t0, 5.0, WEB_BL_WARM_N);
    long long now = last + WEEK; /* same hour of week, a week later */
    web_rollup_add(&ru, WM_HOST_CONNS, "10.0.0.5", 5.0, now - 1);
    for (int i = 0; i < WEB_ANOM_STREAK_MIN; i++) {
        long long t = now + i * 60;
        seed(WEB_TIER_MINUTE, WM_HOST_CONNS, "10.0.0.5", t - 60, 500.0);
        web_anomaly_step(&an, &bl, &ru, &st, NULL, t, 0);
    }
    WT_HAS(anomalies(), "\"kind\":\"rate\"");
    WT_HAS(anomalies(), "\"open\":true");
    done();
}

/* The same baseline, but "now" keeps matching the quiet pattern: the
 * acceptance case's other half ("nothing fires on the quiet stream").
 * Mutating WEB_ANOM_Z_THRESHOLD to 0 would fire this and is exactly
 * the kind of change this test exists to catch. */
static void test_a1_quiet_stream_fires_nothing(void) {
    fresh();
    long long t0 = 1792627200;
    long long last = warm(WM_HOST_CONNS, "10.0.0.6", t0, 5.0, WEB_BL_WARM_N);
    long long now = last + WEEK;
    web_rollup_add(&ru, WM_HOST_CONNS, "10.0.0.6", 5.0, now - 1);
    for (int i = 0; i < WEB_ANOM_STREAK_MIN; i++) {
        long long t = now + i * 60;
        seed(WEB_TIER_MINUTE, WM_HOST_CONNS, "10.0.0.6", t - 60, 5.0);
        web_anomaly_step(&an, &bl, &ru, &st, NULL, t, 0);
    }
    WT_LACKS(anomalies(), "\"key\":\"10.0.0.6\"");
    done();
}

/* A1 requires three *consecutive* minutes: a burst for two minutes,
 * then quiet, never opens. */
static void test_a1_needs_consecutive_minutes(void) {
    fresh();
    long long t0 = 1792627200;
    long long last = warm(WM_HOST_CONNS, "10.0.0.11", t0, 5.0, WEB_BL_WARM_N);
    long long now = last + WEEK;
    web_rollup_add(&ru, WM_HOST_CONNS, "10.0.0.11", 5.0, now - 1);
    double v[] = { 500.0, 500.0, 5.0, 500.0 };
    for (int i = 0; i < 4; i++) {
        long long t = now + i * 60;
        seed(WEB_TIER_MINUTE, WM_HOST_CONNS, "10.0.0.11", t - 60, v[i]);
        web_anomaly_step(&an, &bl, &ru, &st, NULL, t, 0);
    }
    WT_LACKS(anomalies(), "\"open\":true");
    done();
}

/* A3: a device normally absent at this hour of the week, present now. */
static void test_a3_fires_for_off_hours_presence(void) {
    fresh();
    long long t0 = 1792627200;
    long long t_night = t0, t_day = t0 + 12 * HOUR;
    int weeks = WEB_ANOM_A3_MIN_N + 1;
    warm(WM_DEV_PRESENT, "aa:bb:cc:dd:ee:01", t_night, 1.0, weeks);
    long long last_day = warm(WM_DEV_PRESENT, "aa:bb:cc:dd:ee:01", t_day, 0.0,
                              weeks);
    long long now = last_day + WEEK;
    web_rollup_add(&ru, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:01", 1.0, now - 1);
    seed(WEB_TIER_MINUTE, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:01", now - 60, 1.0);
    web_anomaly_step(&an, &bl, &ru, &st, NULL, now, 0);
    WT_HAS(anomalies(), "\"kind\":\"hours\"");
    done();
}

/* The same baseline, presence during its normal (night) hour: no
 * episode. Mutating the mean threshold comparison from < to <= would
 * not flip this one (0.0 is still < WEB_ANOM_A3_MEAN_MAX), so this
 * pins the night cell's *high* mean rather than the threshold itself. */
static void test_a3_silent_during_normal_hours(void) {
    fresh();
    long long t0 = 1792627200;
    long long t_night = t0, t_day = t0 + 12 * HOUR;
    int weeks = WEB_ANOM_A3_MIN_N + 1;
    long long last_night = warm(WM_DEV_PRESENT, "aa:bb:cc:dd:ee:02", t_night,
                                1.0, weeks);
    warm(WM_DEV_PRESENT, "aa:bb:cc:dd:ee:02", t_day, 0.0, weeks);
    long long now = last_night + WEEK;
    web_rollup_add(&ru, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:02", 1.0, now - 1);
    seed(WEB_TIER_MINUTE, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:02", now - 60, 1.0);
    web_anomaly_step(&an, &bl, &ru, &st, NULL, now, 0);
    WT_LACKS(anomalies(), "\"kind\":\"hours\"");
    done();
}

/* A8: a chatty-DNS host, over threshold on both legs. */
static void test_a8_fires_on_chatty_dns(void) {
    fresh();
    long long now = 1792627200 + 7200;
    web_rollup_add(&ru, WM_DNS_QUERIES, "10.0.0.7", 1.0, now - 1);
    for (int i = 0; i < 10; i++) {
        long long t = now - (long long)i * 60;
        seed(WEB_TIER_MINUTE, WM_DNS_QUERIES, "10.0.0.7", t, 3.0);
        seed(WEB_TIER_MINUTE, WM_DNS_NXDOMAIN, "10.0.0.7", t, 2.0);
    }
    web_anomaly_step(&an, &bl, &ru, &st, NULL, now, 0);
    WT_HAS(anomalies(), "\"kind\":\"dns\"");
    done();
}

/* The same query volume, a normal NXDOMAIN share: silent. */
static void test_a8_silent_under_the_share(void) {
    fresh();
    long long now = 1792627200 + 7200;
    web_rollup_add(&ru, WM_DNS_QUERIES, "10.0.0.17", 1.0, now - 1);
    for (int i = 0; i < 10; i++) {
        long long t = now - (long long)i * 60;
        seed(WEB_TIER_MINUTE, WM_DNS_QUERIES, "10.0.0.17", t, 10.0);
        seed(WEB_TIER_MINUTE, WM_DNS_NXDOMAIN, "10.0.0.17", t, 1.0);
    }
    web_anomaly_step(&an, &bl, &ru, &st, NULL, now, 0);
    WT_LACKS(anomalies(), "\"kind\":\"dns\"");
    done();
}

static int find_episode(int kind, int metric, const char *key) {
    for (int i = 0; i < an.cap; i++)
        if (an.ep[i].used && an.ep[i].kind == kind &&
            an.ep[i].metric == metric && !strcmp(an.ep[i].key, key))
            return i;
    return -1;
}

/* A9: a host's first-ever flow.ssh minute fires; the second time it
 * happens (a baseline entry now exists from the hour in between) the
 * rule's own condition no longer matches, so the episode is not
 * touched again — its last_seen stays at the first firing. Mutating
 * scan_a9's "baseline already exists" check to always continue (never
 * skip) would leave it touched at `later` instead, which is exactly
 * what this pins. */
static void test_a9_fires_once_on_first_use(void) {
    fresh();
    long long now = 1792627200 + 7200;
    web_rollup_add(&ru, WM_FLOW_SSH, "10.0.0.8", 1.0, now - 1);
    seed(WEB_TIER_MINUTE, WM_FLOW_SSH, "10.0.0.8", now - 60, 1.0);
    web_anomaly_step(&an, &bl, &ru, &st, NULL, now, 0);
    WT_HAS(anomalies(), "\"kind\":\"proto\"");
    int i = find_episode(WEB_ANOM_A9_PROTO, WM_FLOW_SSH, "10.0.0.8");
    WT_ASSERT(i >= 0);
    WT_EQ(an.ep[i].last_seen, now);

    /* An hour has passed and this host has used flow.ssh before: the
     * baseline now has an entry, so the next minute is not "first". */
    web_baseline_feed(&bl, WM_FLOW_SSH, "10.0.0.8", now, 1.0);
    long long later = now + HOUR + 120;
    seed(WEB_TIER_MINUTE, WM_FLOW_SSH, "10.0.0.8", later - 60, 1.0);
    web_anomaly_step(&an, &bl, &ru, &st, NULL, later, 0);
    i = find_episode(WEB_ANOM_A9_PROTO, WM_FLOW_SSH, "10.0.0.8");
    WT_ASSERT(i >= 0);
    WT_EQ(an.ep[i].last_seen, now);   /* unchanged: not touched again */
    done();
}

/* A10: connected, one record seen, then silence past the threshold. */
static void test_a10_fires_on_sensor_silence(void) {
    fresh();
    web_live_t live;
    web_feed_t feed;
    web_live_init(&live, "unix:/test/sloth.sock");
    web_live_sock_connected(&live, 0);
    web_feed_reset(&feed);
    const char rec[] = "{\"type\":\"device\",\"count\":1}\n";
    web_feed_bytes(&feed, &live, rec, strlen(rec), 1000);
    long long now = 1792627200;
    long long ms_past = 1000 + (WEB_ANOM_A10_SILENCE_S + 5) * 1000LL;
    web_anomaly_step(&an, &bl, &ru, &st, &live, now, ms_past);
    WT_HAS(anomalies(), "\"kind\":\"sensor\"");
    web_live_destroy(&live);
    done();
}

/* The same connection, well inside the heartbeat window: silent. */
static void test_a10_silent_before_the_threshold(void) {
    fresh();
    web_live_t live;
    web_feed_t feed;
    web_live_init(&live, "unix:/test/sloth.sock");
    web_live_sock_connected(&live, 0);
    web_feed_reset(&feed);
    const char rec[] = "{\"type\":\"device\",\"count\":1}\n";
    web_feed_bytes(&feed, &live, rec, strlen(rec), 1000);
    long long now = 1792627200;
    web_anomaly_step(&an, &bl, &ru, &st, &live, now, 1000 + 5000);
    WT_LACKS(anomalies(), "\"kind\":\"sensor\"");
    web_live_destroy(&live);
    done();
}

/* A no-op without a store: every rule here needs the minute or hour
 * tier, so the step must not touch the baseline or the episode table
 * at all when store is NULL (a WITH_SQLITE=0 build, or none opened). */
static void test_no_store_is_a_noop(void) {
    fresh();
    web_rollup_add(&ru, WM_HOST_RX, "10.0.0.20", 1.0, 1792627200);
    web_anomaly_step(&an, &bl, &ru, NULL, NULL, 1792627200, 0);
    web_anomaly_step(&an, &bl, &ru, NULL, NULL, 1792627200 + 3600, 0);
    WT_EQ(web_baseline_count(&bl), 0);
    const char *j = anomalies();
    WT_HAS(j, "\"anomalies\":[]");
    done();
}

/* An open episode that stops firing closes after WEB_ANOM_CLEAR_TICKS
 * quiet minutes, rather than staying open forever. */
static void test_open_episode_closes_after_quiet_ticks(void) {
    fresh();
    long long t0 = 1792627200;
    long long last = warm(WM_HOST_CONNS, "10.0.0.12", t0, 5.0, WEB_BL_WARM_N);
    long long now = last + WEEK;
    web_rollup_add(&ru, WM_HOST_CONNS, "10.0.0.12", 5.0, now - 1);
    for (int i = 0; i < WEB_ANOM_STREAK_MIN; i++) {
        long long t = now + i * 60;
        seed(WEB_TIER_MINUTE, WM_HOST_CONNS, "10.0.0.12", t - 60, 500.0);
        web_anomaly_step(&an, &bl, &ru, &st, NULL, t, 0);
    }
    WT_HAS(anomalies(), "\"open\":true");
    long long quiet_from = now + WEB_ANOM_STREAK_MIN * 60;
    for (int i = 0; i < WEB_ANOM_CLEAR_TICKS; i++) {
        long long t = quiet_from + i * 60;
        seed(WEB_TIER_MINUTE, WM_HOST_CONNS, "10.0.0.12", t - 60, 5.0);
        web_anomaly_step(&an, &bl, &ru, &st, NULL, t, 0);
    }
    const char *j = anomalies();
    WT_HAS(j, "\"key\":\"10.0.0.12\"");
    WT_HAS(j, "\"open\":false");
    done();
}

void run_anomaly_tests(void) {
    WT_RUN(test_hour_feed_wires_to_baseline);
    WT_RUN(test_a1_fires_on_sustained_burst);
    WT_RUN(test_a1_quiet_stream_fires_nothing);
    WT_RUN(test_a1_needs_consecutive_minutes);
    WT_RUN(test_a3_fires_for_off_hours_presence);
    WT_RUN(test_a3_silent_during_normal_hours);
    WT_RUN(test_a8_fires_on_chatty_dns);
    WT_RUN(test_a8_silent_under_the_share);
    WT_RUN(test_a9_fires_once_on_first_use);
    WT_RUN(test_a10_fires_on_sensor_silence);
    WT_RUN(test_a10_silent_before_the_threshold);
    WT_RUN(test_no_store_is_a_noop);
    WT_RUN(test_open_episode_closes_after_quiet_ticks);
}

#endif
