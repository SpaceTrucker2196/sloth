/* The rollup (#160, M2) without a store, a socket or a clock: samples
 * at hand-picked seconds, buckets read back. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_rollup.h"
#include "wtest.h"

static web_rollup_t ru;
static web_qrow_t   q[WEB_QUEUE_ROWS];

static void fresh(int max_keys, int store_on) {
    char err[64];
    WT_EQ(web_rollup_init(&ru, max_keys, store_on, err, sizeof(err)), 0);
}

static int fine(int m, const char *k, long long from, long long to,
                int with_open, web_point_t *out, int max) {
    int more;
    return web_rollup_fine(&ru, m, k, from, to, with_open, out, max, &more);
}

/* 10 s, 1 min, 1 h boundaries; sum, count, min, max per bucket; the
 * open bucket closed by the first sample of the next. */
static void test_bucket_boundaries_and_aggregates(void) {
    fresh(64, 1);
    const long long T = 1792627200;   /* a whole hour */
    web_rollup_add(&ru, WM_IFACE_RX, "eth0", 4, T + 0);
    web_rollup_add(&ru, WM_IFACE_RX, "eth0", 2, T + 9);
    web_rollup_add(&ru, WM_IFACE_RX, "eth0", 9, T + 9);
    web_point_t p[8];
    /* Nothing closed yet: only the open bucket, and only when asked. */
    WT_EQ(fine(WM_IFACE_RX, "eth0", T, T + 3600, 0, p, 8), 0);
    WT_EQ(fine(WM_IFACE_RX, "eth0", T, T + 3600, 1, p, 8), 1);
    WT_EQ(p[0].t, T);
    WT_EQ(p[0].n, 3);
    WT_ASSERT(p[0].sum == 15 && p[0].min == 2 && p[0].max == 9);
    WT_ASSERT(fabs(web_point_value(WM_IFACE_RX, &p[0]) - 5.0) < 1e-9);

    web_rollup_add(&ru, WM_IFACE_RX, "eth0", 1, T + 10);   /* next bucket */
    WT_EQ(fine(WM_IFACE_RX, "eth0", T, T + 3600, 0, p, 8), 1);
    WT_EQ(p[0].t, T);
    size_t n = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    WT_EQ(n, 1);                         /* only the fine bucket closed */
    WT_EQ(q[0].tier, WEB_TIER_FINE);
    WT_EQ(q[0].t, T);
    WT_HAS(q[0].key, "eth0");

    /* Minute closes at T+60, hour at T+3600, whatever arrives. */
    web_rollup_close_due(&ru, T + 59);
    n = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    WT_EQ(n, 1);                         /* [T+10, T+20) only */
    WT_EQ(q[0].t, T + 10);
    web_rollup_close_due(&ru, T + 60);
    n = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    WT_EQ(n, 1);
    WT_EQ(q[0].tier, WEB_TIER_MINUTE);
    WT_EQ(q[0].t, T);
    WT_EQ(q[0].n, 4);
    WT_ASSERT(q[0].sum == 16 && q[0].min == 1 && q[0].max == 9);
    web_rollup_close_due(&ru, T + 3599);
    WT_EQ(web_rollup_take(&ru, q, WEB_QUEUE_ROWS), 0);
    web_rollup_close_due(&ru, T + 3600);
    n = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    WT_EQ(n, 1);
    WT_EQ(q[0].tier, WEB_TIER_HOUR);
    WT_EQ(q[0].t, T);
    web_rollup_destroy(&ru);
}

/* Counters read as their sum, presence as its max. */
static void test_point_value_by_kind(void) {
    web_point_t p = { 0, 12, 1, 5, 4 };
    WT_ASSERT(web_point_value(WM_DNS_QUERIES, &p) == 12);
    WT_ASSERT(web_point_value(WM_DEV_PRESENT, &p) == 5);
    WT_ASSERT(web_point_value(WM_HOST_RX, &p) == 3);
    p.n = 0;
    WT_ASSERT(web_point_value(WM_HOST_RX, &p) == 0);
}

/* A non-finite value never enters a bucket; a huge one is clamped. */
static void test_values_bounded(void) {
    fresh(64, 0);
    const long long T = 1792627200;
    web_rollup_add(&ru, WM_HOST_RX, "10.0.0.1", NAN, T);
    web_rollup_add(&ru, WM_HOST_RX, "10.0.0.1", INFINITY, T);
    web_point_t p[2];
    WT_EQ(fine(WM_HOST_RX, "10.0.0.1", T, T + 10, 1, p, 2), 0);
    web_rollup_add(&ru, WM_HOST_RX, "10.0.0.1", 1e300, T);
    WT_EQ(fine(WM_HOST_RX, "10.0.0.1", T, T + 10, 1, p, 2), 1);
    WT_ASSERT(p[0].max == WEB_VALUE_MAX);
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.clamped, 1);
    /* An empty or over-long key is not a series. */
    char big[WEB_KEY_MAX + 8];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    web_rollup_add(&ru, WM_HOST_RX, "", 1, T);
    web_rollup_add(&ru, WM_HOST_RX, big, 1, T);
    web_rollup_stats(&ru, &st);
    WT_EQ(st.keys[WEB_KC_HOST], 1);
    web_rollup_destroy(&ru);
}

/* §5.2: N device keys, N/2 host keys, least recently seen evicted,
 * its open buckets flushed first, evictions counted per class. Global
 * metrics are never evicted. Seen red with the LRU pick mutated to
 * evict slot 0 (the most recently refreshed key went instead). */
static void test_key_classes_are_bounded_lru(void) {
    fresh(16, 1);
    const long long T = 1792627200;
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.caps[WEB_KC_DEV], 16);
    WT_EQ(st.caps[WEB_KC_HOST], 8);
    WT_EQ(st.caps[WEB_KC_LABEL], WEB_LABEL_KEYS);
    WT_EQ(st.caps[WEB_KC_GLOBAL], 1);

    char k[32];
    for (int i = 0; i < 8; i++) {
        snprintf(k, sizeof(k), "10.0.0.%d", i + 1);
        web_rollup_add(&ru, WM_HOST_CONNS, k, i, T + i);
    }
    web_rollup_add(&ru, WM_CONNS_TOTAL, "", 5, T);
    /* Refresh the oldest, so the second-oldest is the one to go. */
    web_rollup_add(&ru, WM_HOST_CONNS, "10.0.0.1", 1, T + 20);
    web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    web_rollup_add(&ru, WM_HOST_CONNS, "10.0.0.99", 1, T + 21);
    web_rollup_stats(&ru, &st);
    WT_EQ(st.keys[WEB_KC_HOST], 8);
    WT_EQ(st.evictions[WEB_KC_HOST], 1);
    WT_EQ(st.evictions[WEB_KC_DEV], 0);
    web_keyinfo_t ki[16];
    int total;
    int n = web_rollup_keys(&ru, WM_HOST_CONNS, ki, 16, &total);
    WT_EQ(n, 8);
    WT_EQ(total, 8);
    WT_ASSERT(!strcmp(ki[0].key, "10.0.0.99"));    /* newest first */
    WT_ASSERT(!strcmp(ki[1].key, "10.0.0.1"));
    int has2 = 0, has1 = 0;
    for (int i = 0; i < n; i++) {
        if (!strcmp(ki[i].key, "10.0.0.2")) has2 = 1;
        if (!strcmp(ki[i].key, "10.0.0.1")) has1 = 1;
    }
    WT_EQ(has2, 0);
    WT_EQ(has1, 1);
    /* The evicted key's open buckets were flushed. 10.0.0.2 had one
     * sample and lived under 10 s, a one-shot key: its fine row reached
     * the store queue with its value, its minute and hour rows were
     * dropped and counted (test_eviction_oneshot_and_lived has a key
     * that lived). */
    size_t qn = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    int flushed = 0;
    for (size_t i = 0; i < qn; i++)
        if (!strcmp(q[i].key, "10.0.0.2") && q[i].metric == WM_HOST_CONNS &&
            q[i].sum == 1 && q[i].tier == WEB_TIER_FINE)
            flushed++;
    WT_EQ(flushed, 1);
    web_rollup_stats(&ru, &st);
    WT_EQ(st.oneshot_dropped, 2);
    /* The device class is separate: filling it leaves hosts alone. */
    for (int i = 0; i < 40; i++) {
        snprintf(k, sizeof(k), "02:00:00:00:00:%02x", i);
        web_rollup_add(&ru, WM_DEV_PRESENT, k, 1, T + 30 + i);
    }
    web_rollup_stats(&ru, &st);
    WT_EQ(st.keys[WEB_KC_DEV], 16);
    WT_EQ(st.evictions[WEB_KC_DEV], 24);
    WT_EQ(st.evictions[WEB_KC_HOST], 1);
    WT_EQ(st.keys[WEB_KC_GLOBAL], 1);
    web_point_t p[4];
    WT_EQ(fine(WM_CONNS_TOTAL, "", T, T + 100, 1, p, 4), 1);
    web_rollup_destroy(&ru);
}

/* What an eviction writes. A key with two samples, or one that lived
 * a fine bucket or longer, has all three of its open buckets flushed;
 * a key with one sample that lived under 10 s (what key churn is) has
 * only its fine row flushed, and its minute and hour rows are dropped
 * and counted, so churn cannot fill the 30-day and 400-day tiers. Seen
 * red with key_oneshot() always 0 (the churn key's minute and hour
 * rows were queued, oneshot_dropped stayed 0), with it always 1 (the
 * keys that lived lost theirs), and with its lifetime test alone
 * removed (10.0.0.2 lost its minute and hour rows). */
static void test_eviction_oneshot_and_lived(void) {
    fresh(16, 1);                         /* 8 host keys */
    const long long T = 1792627200;
    char k[32];
    /* 10.0.0.1: two samples in one second. 10.0.0.2: one sample in
     * each of two series, at T and T + 15 (one per series, but it lived
     * past a fine bucket). 10.0.0.3..8: one each. */
    web_rollup_add(&ru, WM_HOST_CONNS, "10.0.0.1", 1, T);
    web_rollup_add(&ru, WM_HOST_CONNS, "10.0.0.1", 2, T);
    web_rollup_add(&ru, WM_HOST_CONNS, "10.0.0.2", 1, T);
    for (int i = 3; i <= 8; i++) {
        snprintf(k, sizeof(k), "10.0.0.%d", i);
        web_rollup_add(&ru, WM_HOST_CONNS, k, 1, T + 16);
    }
    web_rollup_add(&ru, WM_HOST_RX, "10.0.0.2", 1, T + 15);
    WT_EQ(web_rollup_take(&ru, q, WEB_QUEUE_ROWS), 0);
    /* Three new keys evict 10.0.0.1 (T), 10.0.0.2 (T + 15), then 10.0.0.3
     * (T + 16, one sample: one-shot). */
    for (int i = 0; i < 3; i++) {
        snprintf(k, sizeof(k), "10.0.1.%d", i);
        web_rollup_add(&ru, WM_HOST_CONNS, k, 1, T + 17);
    }
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.evictions[WEB_KC_HOST], 3);
    size_t qn = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    int tiers[3][WEB_TIER_COUNT];
    memset(tiers, 0, sizeof(tiers));
    for (size_t i = 0; i < qn; i++)
        for (int j = 0; j < 3; j++) {
            snprintf(k, sizeof(k), "10.0.0.%d", j + 1);
            if (!strcmp(q[i].key, k) && q[i].metric == WM_HOST_CONNS)
                tiers[j][q[i].tier]++;
        }
    for (int t = 0; t < WEB_TIER_COUNT; t++) {
        WT_EQ(tiers[0][t], 1);
        WT_EQ(tiers[1][t], 1);
    }
    WT_EQ(tiers[2][WEB_TIER_FINE], 1);
    WT_EQ(tiers[2][WEB_TIER_MINUTE], 0);
    WT_EQ(tiers[2][WEB_TIER_HOUR], 0);
    WT_EQ(st.oneshot_dropped, 2);
    /* A key that is never evicted is never one-shot: closed as due. */
    web_rollup_close_all(&ru);
    web_rollup_stats(&ru, &st);
    WT_EQ(st.oneshot_dropped, 2);
    web_rollup_destroy(&ru);
}

/* Newest first, bounded, half-open. Two ring rows of one series for
 * one bucket (close_all() and then more samples inside it) are merged
 * into one. A key evicted and back is a new series instance, so the
 * rows before its eviction are found by (metric, key) only through the
 * store. */
static void test_ring_query_merges_and_bounds(void) {
    fresh(16, 0);
    const long long T = 1792627200;
    for (int b = 0; b < 30; b++)
        web_rollup_add(&ru, WM_HOST_RX, "10.0.0.1", b, T + b * 10);
    web_point_t p[64];
    int more;
    int n = web_rollup_fine(&ru, WM_HOST_RX, "10.0.0.1", T, T + 300, 1, p, 64,
                            &more);
    WT_EQ(n, 30);
    WT_EQ(more, 0);
    WT_EQ(p[0].t, T + 290);                  /* newest first */
    WT_EQ(p[29].t, T);
    n = web_rollup_fine(&ru, WM_HOST_RX, "10.0.0.1", T, T + 300, 1, p, 10, &more);
    WT_EQ(n, 10);
    WT_EQ(more, 1);
    WT_EQ(p[9].t, T + 200);
    /* [from, to) is half-open. */
    n = web_rollup_fine(&ru, WM_HOST_RX, "10.0.0.1", T + 10, T + 30, 1, p, 64,
                        &more);
    WT_EQ(n, 2);
    WT_EQ(p[0].t, T + 20);
    WT_EQ(p[1].t, T + 10);
    /* Unknown key, unknown metric: nothing. */
    WT_EQ(fine(WM_HOST_RX, "10.0.0.2", T, T + 300, 1, p, 64), 0);
    WT_EQ(fine(-1, "10.0.0.1", T, T + 300, 1, p, 64), 0);
    web_rollup_destroy(&ru);

    fresh(16, 0);
    web_rollup_add(&ru, WM_HOST_TX, "10.0.0.1", 3, T + 1);
    web_rollup_close_all(&ru);              /* a partial bucket in the ring */
    web_rollup_add(&ru, WM_HOST_TX, "10.0.0.1", 5, T + 2);
    n = fine(WM_HOST_TX, "10.0.0.1", T, T + 10, 1, p, 64);
    WT_EQ(n, 1);
    WT_EQ(p[0].n, 2);
    WT_ASSERT(p[0].sum == 8 && p[0].min == 3 && p[0].max == 5);
    web_rollup_destroy(&ru);
}

/* With no store, nothing is queued (and nothing is dropped for lack of
 * room in a queue that does not exist). */
static void test_no_store_no_queue(void) {
    fresh(16, 0);
    const long long T = 1792627200;
    for (int i = 0; i < 100; i++)
        web_rollup_add(&ru, WM_IFACE_TX, "eth0", i, T + i * 10);
    WT_EQ(web_rollup_take(&ru, q, WEB_QUEUE_ROWS), 0);
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.q_dropped, 0);
    WT_EQ(st.ring_rows, 99);
    WT_EQ(st.rows_closed[WEB_TIER_FINE], 99);
    web_rollup_destroy(&ru);
}

/* The store queue is bounded: past WEB_QUEUE_ROWS a closed bucket is
 * dropped and counted (queue_dropped on /api/health), never written
 * over a queued one, so what the store thread takes is the oldest
 * rows. One global series, a sample per 10 s bucket: each add closes
 * the previous fine bucket, every sixth a minute, every 360th an hour,
 * in that order, which the test replays to know which row is the last
 * one the queue kept. Seen red with the full branch writing the last
 * slot instead of dropping (q_dropped stayed 0 and the last row taken
 * was the newest). */
static void test_queue_full_drops_newest_and_counts(void) {
    fresh(16, 1);
    const long long T = 1792627200;
    const int adds = 30000;
    long long kept_t = -1;
    int kept_tier = -1;
    size_t emitted = 0;
    for (int i = 0; i < adds; i++) {
        long long now = T + (long long)i * 10;
        web_rollup_add(&ru, WM_CONNS_TOTAL, "", i, now);
        if (i == 0) continue;
        static const int step[WEB_TIER_COUNT] = { 10, 60, 3600 };
        for (int t = 0; t < WEB_TIER_COUNT; t++) {
            long long prev = now - 10;
            if ((now - now % step[t]) == (prev - prev % step[t])) continue;
            if (++emitted == WEB_QUEUE_ROWS) {
                kept_t = prev - prev % step[t];
                kept_tier = t;
            }
        }
    }
    WT_ASSERT(emitted > WEB_QUEUE_ROWS);
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.queue_rows, WEB_QUEUE_ROWS);
    WT_EQ(st.q_dropped, emitted - WEB_QUEUE_ROWS);
    WT_EQ(st.rows_closed[WEB_TIER_FINE] + st.rows_closed[WEB_TIER_MINUTE] +
          st.rows_closed[WEB_TIER_HOUR], emitted);
    size_t n = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    WT_EQ(n, WEB_QUEUE_ROWS);
    WT_EQ(q[0].tier, WEB_TIER_FINE);
    WT_EQ(q[0].t, T);
    WT_EQ(q[n - 1].tier, kept_tier);
    WT_EQ(q[n - 1].t, kept_t);
    WT_ASSERT(q[n - 1].t < T + (long long)(adds - 1) * 10 - 3600);
    WT_EQ(web_rollup_take(&ru, q, WEB_QUEUE_ROWS), 0);
    web_rollup_destroy(&ru);
}

static void test_catalogue(void) {
    WT_EQ(web_metric_find("iface.rx_rate"), WM_IFACE_RX);
    WT_EQ(web_metric_find("flow.mqtt"), WM_FLOW_MQTT);
    WT_EQ(web_metric_find("iface.rx_rate "), -1);
    WT_EQ(web_metric_find(""), -1);
    WT_EQ(web_tier_find("fine"), WEB_TIER_FINE);
    WT_EQ(web_tier_find("hour"), WEB_TIER_HOUR);
    WT_EQ(web_tier_find("10s"), -1);
    WT_EQ(web_tier_step(WEB_TIER_MINUTE), 60);
    for (int i = 0; i < WM_COUNT; i++) {
        WT_ASSERT(web_metric_defs[i].name != NULL);
        /* A global metric has no key kind, and only a global one. */
        WT_EQ(web_metric_defs[i].kclass == WEB_KC_GLOBAL,
              web_metric_defs[i].keykind[0] == '\0');
    }
}

void run_rollup_tests(void) {
    WT_RUN(test_bucket_boundaries_and_aggregates);
    WT_RUN(test_point_value_by_kind);
    WT_RUN(test_values_bounded);
    WT_RUN(test_key_classes_are_bounded_lru);
    WT_RUN(test_eviction_oneshot_and_lived);
    WT_RUN(test_ring_query_merges_and_bounds);
    WT_RUN(test_no_store_no_queue);
    WT_RUN(test_queue_full_drops_newest_and_counts);
    WT_RUN(test_catalogue);
}
