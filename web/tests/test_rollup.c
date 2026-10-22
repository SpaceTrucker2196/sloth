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
 * open bucket closed by the first sample of the next. A global series,
 * which is established from its first sample (a key is established
 * once its samples span a minute: test_eviction_churn_on_whole_life). */
static void test_bucket_boundaries_and_aggregates(void) {
    fresh(64, 1);
    const long long T = 1792627200;   /* a whole hour */
    web_rollup_add(&ru, WM_CONNS_TOTAL, "", 4, T + 0);
    web_rollup_add(&ru, WM_CONNS_TOTAL, "", 2, T + 9);
    web_rollup_add(&ru, WM_CONNS_TOTAL, "", 9, T + 9);
    web_point_t p[8];
    /* Nothing closed yet: only the open bucket, and only when asked. */
    WT_EQ(fine(WM_CONNS_TOTAL, "", T, T + 3600, 0, p, 8), 0);
    WT_EQ(fine(WM_CONNS_TOTAL, "", T, T + 3600, 1, p, 8), 1);
    WT_EQ(p[0].t, T);
    WT_EQ(p[0].n, 3);
    WT_ASSERT(p[0].sum == 15 && p[0].min == 2 && p[0].max == 9);
    WT_ASSERT(fabs(web_point_value(WM_CONNS_TOTAL, &p[0]) - 5.0) < 1e-9);

    web_rollup_add(&ru, WM_CONNS_TOTAL, "", 1, T + 10);    /* next bucket */
    WT_EQ(fine(WM_CONNS_TOTAL, "", T, T + 3600, 0, p, 8), 1);
    WT_EQ(p[0].t, T);
    size_t n = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    WT_EQ(n, 1);                         /* only the fine bucket closed */
    WT_EQ(q[0].tier, WEB_TIER_FINE);
    WT_EQ(q[0].t, T);
    WT_EQ(q[0].metric, WM_CONNS_TOTAL);
    WT_EQ(q[0].key[0], '\0');

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
    /* The evicted key's open buckets were flushed. 10.0.0.2's samples
     * never spanned a minute: its fine row reached the store queue with
     * its value, its minute and hour rows were dropped and counted
     * (test_eviction_churn_on_whole_life has keys that were established). */
    size_t qn = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    int flushed = 0;
    for (size_t i = 0; i < qn; i++)
        if (!strcmp(q[i].key, "10.0.0.2") && q[i].metric == WM_HOST_CONNS &&
            q[i].sum == 1 && q[i].tier == WEB_TIER_FINE)
            flushed++;
    WT_EQ(flushed, 1);
    web_rollup_stats(&ru, &st);
    WT_EQ(st.churn_dropped, 2);
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

/* Per key and tier, the queued rows of metric m for keys k[0..nk). */
static void tally(const char *const *k, int nk, int m, size_t qn,
                  int out[][WEB_TIER_COUNT]) {
    for (size_t i = 0; i < qn; i++)
        for (int j = 0; j < nk; j++)
            if (!strcmp(q[i].key, k[j]) && q[i].metric == m)
                out[j][q[i].tier]++;
}

/* Feed one sample and run the store thread's close, as it would. */
static void add_step(int m, const char *k, double v, long long now) {
    web_rollup_add(&ru, m, k, v, now);
    web_rollup_close_due(&ru, now);
}

/* What an eviction writes is decided on the key's whole life. A key
 * whose samples never spanned a minute is churn however many it took:
 * two (A) or three (B) samples, each key crossing a minute and an hour
 * boundary, and the store thread closing buckets every second as they
 * fall due. Their fine rows are written; their minute and hour rows
 * are held, never queued, and dropped and counted at eviction. A key
 * whose samples spanned exactly a minute (C) is established and keeps
 * all of its rows.
 *
 * Seen red, one mutation at a time: key_flush() emitting an
 * unestablished key's long-tier rows (A and B queued minute and hour
 * rows, churn_dropped 0); close_where()'s skip of unestablished long
 * tiers removed (A's T-60 minute row was pushed out of the held slot
 * when its T minute fell due at T+60); the establishing test as
 * "> WEB_MINUTE_S" (C lost its minute and hour rows, and so did D in
 * test_unestablished_key_held_not_lost). */
static void test_eviction_churn_on_whole_life(void) {
    fresh(16, 1);                         /* 8 host keys */
    const long long T = 1792627200;       /* a whole hour */
    static const char *const K[] = { "10.0.0.1", "10.0.0.2", "10.0.0.3" };
    add_step(WM_HOST_CONNS, K[0], 1, T - 5);
    add_step(WM_HOST_CONNS, K[1], 1, T - 4);
    add_step(WM_HOST_CONNS, K[2], 1, T - 5);
    add_step(WM_HOST_CONNS, K[1], 1, T + 2);
    add_step(WM_HOST_CONNS, K[0], 1, T + 5);
    add_step(WM_HOST_CONNS, K[1], 1, T + 50);
    add_step(WM_HOST_CONNS, K[2], 1, T + 55);
    char k[32];
    for (int i = 4; i <= 8; i++) {
        snprintf(k, sizeof(k), "10.0.0.%d", i);
        add_step(WM_HOST_CONNS, k, 1, T + 56);
    }
    int tiers[3][WEB_TIER_COUNT];
    memset(tiers, 0, sizeof(tiers));
    for (long long now = T + 57; now <= T + 61; now++) web_rollup_close_due(&ru, now);
    size_t qn = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    tally(K, 3, WM_HOST_CONNS, qn, tiers);
    /* Nothing of A or B's long tiers left memory while they lived. */
    WT_EQ(tiers[0][WEB_TIER_MINUTE] + tiers[0][WEB_TIER_HOUR], 0);
    WT_EQ(tiers[1][WEB_TIER_MINUTE] + tiers[1][WEB_TIER_HOUR], 0);
    /* Three new keys evict A (T+5), B (T+50), C (T+55). */
    for (int i = 0; i < 3; i++) {
        snprintf(k, sizeof(k), "10.0.1.%d", i);
        add_step(WM_HOST_CONNS, k, 1, T + 61);
    }
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.evictions[WEB_KC_HOST], 3);
    qn = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    tally(K, 3, WM_HOST_CONNS, qn, tiers);
    WT_EQ(tiers[0][WEB_TIER_FINE], 2);           /* T-10, T */
    WT_EQ(tiers[0][WEB_TIER_MINUTE], 0);
    WT_EQ(tiers[0][WEB_TIER_HOUR], 0);
    WT_EQ(tiers[1][WEB_TIER_FINE], 3);           /* T-10, T, T+50 */
    WT_EQ(tiers[1][WEB_TIER_MINUTE], 0);
    WT_EQ(tiers[1][WEB_TIER_HOUR], 0);
    WT_EQ(tiers[2][WEB_TIER_FINE], 2);           /* T-10, T+50 */
    WT_EQ(tiers[2][WEB_TIER_MINUTE], 2);         /* T-60, T */
    WT_EQ(tiers[2][WEB_TIER_HOUR], 2);           /* T-3600, T */
    /* A and B: a held and an open row in each of two tiers. */
    WT_EQ(st.churn_dropped, 8);
    web_rollup_close_all(&ru);
    web_rollup_stats(&ru, &st);
    WT_EQ(st.churn_dropped, 8);
    web_rollup_destroy(&ru);
}

/* An unestablished key that is not evicted loses nothing. Seen again a
 * minute after it was first (D), its held rows are released then, with
 * their values; still unestablished at shutdown (E), close_all()
 * writes its held and open rows. Seen red with release_held() left out
 * of web_rollup_add() (D's T-60 minute and T-3600 hour rows never came)
 * and out of close_where() (E's held rows never came). */
static void test_unestablished_key_held_not_lost(void) {
    fresh(16, 1);
    const long long T = 1792627200;
    static const char *const K[] = { "10.0.0.4", "10.0.0.5" };
    add_step(WM_HOST_RX, K[0], 3, T - 5);
    add_step(WM_HOST_RX, K[1], 3, T - 5);
    add_step(WM_HOST_RX, K[0], 4, T + 5);
    add_step(WM_HOST_RX, K[1], 4, T + 5);
    for (long long now = T + 6; now < T + 55; now++) web_rollup_close_due(&ru, now);
    int tiers[2][WEB_TIER_COUNT];
    memset(tiers, 0, sizeof(tiers));
    size_t qn = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    tally(K, 2, WM_HOST_RX, qn, tiers);
    WT_EQ(tiers[0][WEB_TIER_MINUTE] + tiers[0][WEB_TIER_HOUR], 0);
    add_step(WM_HOST_RX, K[0], 5, T + 55);       /* spans 60 s: established */
    qn = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    int got_min = 0, got_hour = 0;
    for (size_t i = 0; i < qn; i++) {
        if (strcmp(q[i].key, K[0])) continue;
        if (q[i].tier == WEB_TIER_MINUTE && q[i].t == T - 60 && q[i].sum == 3)
            got_min++;
        if (q[i].tier == WEB_TIER_HOUR && q[i].t == T - 3600 && q[i].sum == 3)
            got_hour++;
    }
    WT_EQ(got_min, 1);
    WT_EQ(got_hour, 1);
    /* Established, its T minute closes when due. */
    web_rollup_close_due(&ru, T + 60);
    qn = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    memset(tiers, 0, sizeof(tiers));
    tally(K, 2, WM_HOST_RX, qn, tiers);
    WT_EQ(tiers[0][WEB_TIER_MINUTE], 1);
    WT_EQ(tiers[1][WEB_TIER_MINUTE], 0);
    web_rollup_close_all(&ru);
    qn = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    memset(tiers, 0, sizeof(tiers));
    tally(K, 2, WM_HOST_RX, qn, tiers);
    WT_EQ(tiers[1][WEB_TIER_MINUTE], 2);         /* T-60 held, T open */
    WT_EQ(tiers[1][WEB_TIER_HOUR], 2);           /* T-3600 held, T open */
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.churn_dropped, 0);
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
    WT_RUN(test_eviction_churn_on_whole_life);
    WT_RUN(test_unestablished_key_held_not_lost);
    WT_RUN(test_ring_query_merges_and_bounds);
    WT_RUN(test_no_store_no_queue);
    WT_RUN(test_queue_full_drops_newest_and_counts);
    WT_RUN(test_catalogue);
}
