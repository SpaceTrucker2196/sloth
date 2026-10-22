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
    WT_EQ(st.caps[WEB_KC_IFACE], WEB_IFACE_KEYS);
    WT_EQ(st.caps[WEB_KC_CHANNEL], WEB_CHANNEL_KEYS);
    WT_EQ(st.caps[WEB_KC_ALERT], WEB_ALERT_KEYS);
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

/* The store queue is bounded: past its cap a closed bucket is dropped
 * and counted (queue_dropped on /api/health), never written over a
 * queued one of a longer tier. Fine rows go first: a minute or hour row
 * arriving at a full queue takes the newest queued fine row's place,
 * and a fine row arriving then is dropped itself, so what the store
 * thread takes is every minute and hour row and the oldest fine rows.
 * One global series, a sample per 10 s bucket: each add closes the
 * previous fine bucket, every sixth a minute, every 360th an hour.
 * Seen red with q_slot() dropping whatever arrives at a full queue (the
 * old rule): 4,670 of the 4,999 minute rows and 77 of the 83 hour rows
 * were kept. */
static void test_queue_full_drops_fine_first_and_counts(void) {
    fresh(16, 1);
    const long long T = 1792627200;
    const int adds = 30000;
    size_t emitted[WEB_TIER_COUNT] = { 0, 0, 0 };
    for (int i = 0; i < adds; i++) {
        long long now = T + (long long)i * 10;
        web_rollup_add(&ru, WM_CONNS_TOTAL, "", i, now);
        if (i == 0) continue;
        static const int step[WEB_TIER_COUNT] = { 10, 60, 3600 };
        for (int t = 0; t < WEB_TIER_COUNT; t++) {
            long long prev = now - 10;
            if ((now - now % step[t]) != (prev - prev % step[t])) emitted[t]++;
        }
    }
    size_t all = emitted[0] + emitted[1] + emitted[2];
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    /* 466 series at most at --web-max-keys 16: the floor applies. */
    WT_EQ(st.queue_cap, WEB_QUEUE_ROWS);
    WT_ASSERT(all > WEB_QUEUE_ROWS);
    WT_EQ(st.queue_rows, WEB_QUEUE_ROWS);
    WT_EQ(st.q_dropped, all - WEB_QUEUE_ROWS);
    WT_EQ(st.rows_closed[WEB_TIER_FINE] + st.rows_closed[WEB_TIER_MINUTE] +
          st.rows_closed[WEB_TIER_HOUR], all);
    size_t n = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    WT_EQ(n, WEB_QUEUE_ROWS);
    size_t got[WEB_TIER_COUNT] = { 0, 0, 0 };
    long long fine_max = -1;
    for (size_t i = 0; i < n; i++) {
        got[q[i].tier]++;
        if (q[i].tier == WEB_TIER_FINE && q[i].t > fine_max) fine_max = q[i].t;
    }
    WT_EQ(got[WEB_TIER_MINUTE], emitted[WEB_TIER_MINUTE]);
    WT_EQ(got[WEB_TIER_HOUR], emitted[WEB_TIER_HOUR]);
    WT_EQ(got[WEB_TIER_FINE], WEB_QUEUE_ROWS - emitted[1] - emitted[2]);
    /* The fine rows kept are the oldest, one per bucket from T on. */
    WT_EQ(fine_max, T + (long long)(got[WEB_TIER_FINE] - 1) * 10);
    WT_EQ(q[0].tier, WEB_TIER_FINE);
    WT_EQ(q[0].t, T);
    WT_EQ(web_rollup_take(&ru, q, WEB_QUEUE_ROWS), 0);
    web_rollup_destroy(&ru);
}

/* What one global series, given sample i at T + 10 i for i in [from,
 * to), closes, in the order the rollup closes it: per add the fine,
 * then the minute, then the hour bucket of the previous sample. sums[]
 * carries the open sums across calls. Returns the rows written. */
typedef struct { int tier; long long t; double sum; } exp_row_t;

static size_t model_rows(long long T, int from, int to, double sums[3],
                         exp_row_t *out) {
    static const long long step[WEB_TIER_COUNT] = { 10, 60, 3600 };
    size_t n = 0;
    for (int i = from; i < to; i++) {
        long long now = T + (long long)i * 10;
        for (int t = 0; t < WEB_TIER_COUNT; t++) {
            if (i > 0 && now % step[t] == 0) {
                out[n].tier = t;
                out[n].t = now - step[t];
                out[n].sum = sums[t];
                n++;
                sums[t] = 0;
            }
            sums[t] += i;
        }
    }
    return n;
}

static void add_global(long long T, int from, int to) {
    for (int i = from; i < to; i++)
        web_rollup_add(&ru, WM_CONNS_TOTAL, "", i, T + (long long)i * 10);
}

/* Rows taken in chunks of chunk, appended to got from *n on. */
static void take_into(web_qrow_t *got, size_t *n, size_t max, size_t chunk) {
    size_t k;
    while (*n < max) {
        size_t want = max - *n < chunk ? max - *n : chunk;
        if ((k = web_rollup_take(&ru, q, want)) == 0) break;
        memcpy(got + *n, q, k * sizeof(*q));
        *n += k;
    }
}

static size_t mismatches(const web_qrow_t *got, const exp_row_t *want,
                         size_t n) {
    size_t bad = 0;
    for (size_t i = 0; i < n; i++)
        if (got[i].tier != want[i].tier || got[i].t != want[i].t ||
            got[i].sum != want[i].sum || got[i].metric != WM_CONNS_TOTAL)
            bad++;
    return bad;
}

/* The queue is a ring (a take moves only what it takes). Fill it, take
 * part, refill past the end of the array, take the rest in chunks that
 * straddle the end: every row comes out once, in closing order, with
 * its contents. Seen red with web_rollup_take() copying only the run up
 * to the end of the array (the rows after the wrap came out as stale
 * slots: 3,235 mismatches). */
static void test_queue_ring_wraps_in_order(void) {
    fresh(16, 1);
    const long long T = 1792627200;              /* a whole hour */
    exp_row_t *want = calloc(64 * 1024, sizeof(*want));
    web_qrow_t *got = calloc(64 * 1024, sizeof(*got));
    WT_ASSERT(want && got);
    if (!want || !got) { free(want); free(got); return; }
    double sums[3] = { 0, 0, 0 };
    size_t nw = model_rows(T, 0, 20000, sums, want);
    add_global(T, 0, 20000);
    size_t ng = 0;
    take_into(got, &ng, 15000, 4096);
    WT_EQ(ng, 15000);
    nw += model_rows(T, 20000, 40000, sums, want + nw);
    add_global(T, 20000, 40000);
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.queue_cap, WEB_QUEUE_ROWS);
    WT_EQ(st.q_dropped, 0);
    WT_EQ(st.queue_rows, nw - 15000);
    /* The live rows run past the end of the array. */
    WT_ASSERT(ru.q_head + st.queue_rows > st.queue_cap);
    take_into(got, &ng, nw + 1, 7001);
    WT_EQ(ng, nw);
    WT_EQ(mismatches(got, want, nw), 0);
    WT_EQ(web_rollup_take(&ru, q, WEB_QUEUE_ROWS), 0);
    free(want);
    free(got);
    web_rollup_destroy(&ru);
}

/* Drop-fine-first holds across the wrap: with the live rows straddling
 * the end of the array, an overfilled queue keeps every minute and hour
 * row and, of the fine rows, the oldest, contiguous from the first one
 * not taken. Seen red with q_slot()'s scan indexing the array instead
 * of the ring (it replaced fine rows below the newest: the fine rows
 * kept were not the oldest). */
static void test_queue_ring_drops_fine_first_across_wrap(void) {
    fresh(16, 1);
    const long long T = 1792627200;
    exp_row_t *want = calloc(64 * 1024, sizeof(*want));
    web_qrow_t *got = calloc(64 * 1024, sizeof(*got));
    WT_ASSERT(want && got);
    if (!want || !got) { free(want); free(got); return; }
    double sums[3] = { 0, 0, 0 };
    size_t nw = model_rows(T, 0, 20000, sums, want);
    add_global(T, 0, 20000);
    size_t ng = 0;
    take_into(got, &ng, 15000, 4096);
    WT_EQ(mismatches(got, want, 15000), 0);
    nw += model_rows(T, 20000, 50000, sums, want + nw);
    add_global(T, 20000, 50000);
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.queue_rows, WEB_QUEUE_ROWS);
    WT_EQ(st.q_dropped, nw - 15000 - WEB_QUEUE_ROWS);
    WT_ASSERT(ru.q_head > 0);
    /* What the rest should be: every minute and hour row after the
     * first 15,000, and the oldest fine rows filling the remainder. */
    size_t long_rows = 0, long_tsum[WEB_TIER_COUNT] = { 0, 0, 0 };
    long long fine_first = -1;
    for (size_t i = 15000; i < nw; i++) {
        if (want[i].tier != WEB_TIER_FINE) {
            long_rows++;
            long_tsum[want[i].tier] += (size_t)(want[i].t - T);
        } else if (fine_first < 0) {
            fine_first = want[i].t;
        }
    }
    size_t fine_keep = WEB_QUEUE_ROWS - long_rows;
    ng = 0;
    take_into(got, &ng, WEB_QUEUE_ROWS + 1, 7001);
    WT_EQ(ng, WEB_QUEUE_ROWS);
    size_t cnt[WEB_TIER_COUNT] = { 0, 0, 0 }, tsum[WEB_TIER_COUNT] = { 0, 0, 0 };
    long long fine_min = -1, fine_max = -1, fine_prev = -1;
    size_t fine_unordered = 0;
    for (size_t i = 0; i < ng; i++) {
        cnt[got[i].tier]++;
        tsum[got[i].tier] += (size_t)(got[i].t - T);
        if (got[i].tier != WEB_TIER_FINE) continue;
        if (fine_min < 0 || got[i].t < fine_min) fine_min = got[i].t;
        if (got[i].t > fine_max) fine_max = got[i].t;
        if (got[i].t <= fine_prev) fine_unordered++;
        fine_prev = got[i].t;
    }
    WT_EQ(cnt[WEB_TIER_MINUTE] + cnt[WEB_TIER_HOUR], long_rows);
    WT_EQ(tsum[WEB_TIER_MINUTE], long_tsum[WEB_TIER_MINUTE]);
    WT_EQ(tsum[WEB_TIER_HOUR], long_tsum[WEB_TIER_HOUR]);
    WT_EQ(cnt[WEB_TIER_FINE], fine_keep);
    WT_EQ(fine_min, fine_first);
    WT_EQ(fine_max, fine_first + (long long)(fine_keep - 1) * 10);
    WT_EQ(fine_unordered, 0);
    free(want);
    free(got);
    web_rollup_destroy(&ru);
}

/* A host that recurs under LRU pressure keeps its long tiers. 300 hosts
 * against 256 host keys, each sending a query every 10 s, staggered, so
 * every host is evicted between each two of its samples. Each stay is
 * under a minute, but the key's life is not: its ghost gives it back its
 * first_seen, so from its first sample a minute after the first it is
 * established, and every minute and hour bucket from then on reaches
 * the queue, partial at each eviction (the store merges them). Only the
 * first minute's long rows are dropped as churn. Seen red with
 * ghost_take() never finding a ghost: 192.168.0.1 queued no minute or
 * hour row (sums 0 against 84). */
static void test_recurring_host_under_lru_keeps_long_tiers(void) {
    fresh(WEB_DEFAULT_MAX_KEYS, 1);       /* 256 host keys */
    const long long T0 = 1792627200;     /* a whole hour */
    const int hosts = 300, span = 900;
    char k[32];
    double sum[WEB_TIER_COUNT] = { 0, 0, 0 };
    size_t rows[WEB_TIER_COUNT] = { 0, 0, 0 };
    for (long long now = T0; now < T0 + span; now++) {
        for (int i = 0; i < hosts; i++) {
            if ((i + 9) % 10 != (now - T0) % 10) continue;   /* 1 at T0+1 */
            snprintf(k, sizeof(k), "192.168.%d.%d", i / 256, i % 256);
            web_rollup_add(&ru, WM_DNS_QUERIES, k, 1, now);
        }
        web_rollup_close_due(&ru, now);
        if (now == T0 + span - 1) web_rollup_close_all(&ru);
        size_t n;
        while ((n = web_rollup_take(&ru, q, WEB_QUEUE_ROWS)) > 0)
            for (size_t i = 0; i < n; i++) {
                if (strcmp(q[i].key, "192.168.0.1") || q[i].metric != WM_DNS_QUERIES)
                    continue;
                rows[q[i].tier]++;
                sum[q[i].tier] += q[i].sum;
            }
    }
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_ASSERT(st.evictions[WEB_KC_HOST] > 20000);
    WT_ASSERT(st.ghost_hits[WEB_KC_HOST] > 20000);
    WT_EQ(st.q_dropped, 0);
    /* 90 samples, at T0+1, T0+11, ... T0+891; the first six fell in the
     * key's first minute. */
    WT_ASSERT(sum[WEB_TIER_FINE] == 90);
    WT_ASSERT(sum[WEB_TIER_MINUTE] == 84);
    WT_ASSERT(sum[WEB_TIER_HOUR] == 84);
    WT_ASSERT(rows[WEB_TIER_MINUTE] > 0 && rows[WEB_TIER_HOUR] > 0);
    /* Each host's first minute only: at most six stays, two rows each. */
    WT_ASSERT(st.churn_dropped <= (unsigned long)hosts * 6 * 2);
    web_rollup_destroy(&ru);
}

/* A scan cannot make an established key forget it was. A (established:
 * samples at T and T+60) is evicted; then 2,000 keys of one sample each
 * churn through the class and its ghost table (32 entries at 8 host
 * keys); A comes back for one sample and is evicted again. Its ghost
 * survived, so that stay's minute and hour rows are written, not
 * dropped as churn. Seen red with ghost_take() never finding a ghost
 * (no minute or hour row of that stay). Whether churn may take an
 * established way is decided only when every way of a set is
 * established, which this case never reaches:
 * test_ghost_table_keeps_established_ways has it. */
static void test_churn_cannot_displace_established_ghost(void) {
    fresh(16, 1);                         /* 8 host keys */
    const long long T = 1792627200;
    char k[32];
    web_rollup_add(&ru, WM_HOST_CONNS, "10.9.9.9", 1, T);
    web_rollup_add(&ru, WM_HOST_CONNS, "10.9.9.9", 1, T + 60);
    for (int i = 0; i < 2000; i++) {
        snprintf(k, sizeof(k), "10.1.%d.%d", i >> 8, i & 255);
        web_rollup_add(&ru, WM_HOST_CONNS, k, 1, T + 61 + i / 100);
        web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    }
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    unsigned long churn0 = st.churn_dropped;
    WT_ASSERT(churn0 > 0);
    web_rollup_add(&ru, WM_HOST_CONNS, "10.9.9.9", 7, T + 200);
    for (int i = 0; i < 8; i++) {
        snprintf(k, sizeof(k), "10.2.0.%d", i);
        web_rollup_add(&ru, WM_HOST_CONNS, k, 1, T + 201);
    }
    size_t n = web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    int minute = 0, hour = 0;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(q[i].key, "10.9.9.9") || q[i].sum != 7) continue;
        if (q[i].tier == WEB_TIER_MINUTE && q[i].t == T + 180) minute++;
        if (q[i].tier == WEB_TIER_HOUR && q[i].t == T) hour++;
    }
    WT_EQ(minute, 1);
    WT_EQ(hour, 1);
    web_rollup_stats(&ru, &st);
    /* Only the eight churn keys still resident, pushed out by A and
     * then by the new keys: a minute and an hour row each. */
    WT_EQ(st.churn_dropped, churn0 + 8 * 2);
    web_rollup_destroy(&ru);
}

/* The ghost table's preference, where it decides: every way of every
 * set holding an established key. 200 established keys, eight at a
 * time, fill all 32 ways; 2,000 unestablished keys then churn through
 * and take none of them. Seen red with ghost_put() letting an
 * unestablished key take an established way (8 of the 32 were taken). */
static int est_ghosts(void) {
    const web_kclass_t *c = &ru.cls[WEB_KC_HOST];
    int n = 0;
    for (int i = 0; i < c->nghost * WEB_GHOST_WAYS; i++)
        if (c->ghost[i].used && c->ghost[i].est) n++;
    return n;
}

static void test_ghost_table_keeps_established_ways(void) {
    fresh(16, 1);                         /* 8 host keys, 32 ghosts */
    const long long T = 1792627200;
    char k[32];
    long long now = T;
    for (int g = 0; g < 25; g++, now += 61)
        for (int pass = 0; pass < 2; pass++)
            for (int i = 0; i < 8; i++) {
                snprintf(k, sizeof(k), "10.3.%d.%d", g, i);
                web_rollup_add(&ru, WM_HOST_CONNS, k, 1, now + pass * 60);
            }
    /* The last group is still resident; the 24 before it are ghosts. */
    const int ways = ru.cls[WEB_KC_HOST].nghost * WEB_GHOST_WAYS;
    WT_EQ(ways, 32);
    WT_EQ(est_ghosts(), ways);
    for (int i = 0; i < 2000; i++) {
        snprintf(k, sizeof(k), "10.4.%d.%d", i >> 8, i & 255);
        web_rollup_add(&ru, WM_HOST_CONNS, k, 1, now + i / 100);
        web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    }
    WT_EQ(est_ghosts(), ways);
    web_rollup_destroy(&ru);
}

/* Interfaces, channels and alert types are established from their first
 * sample: no peer can churn them. An alert type that fired twice in
 * 25 s gets its minute row when the minute ends and its hour row when
 * the hour does, while slothweb runs, not at shutdown. And each kind
 * has its own class: one alert type, then 127 6 GHz channels (64 at a
 * time, so channels evict channels) and an interface for ten minutes,
 * and the alert key stays and nothing is dropped (in the one 128-key
 * class they shared, the quiet alert key was evicted and its rows lost
 * as churn). Seen red with the three label classes churnable (no
 * minute or hour row for the alert, churn_dropped 7,680) and with
 * alerts.fired moved into the channel class (its key evicted). */
static void test_label_keys_established_and_separate(void) {
    fresh(WEB_DEFAULT_MAX_KEYS, 1);
    const long long T = 1792627200;
    web_rollup_add(&ru, WM_ALERTS_FIRED, "9", 1, T + 5);
    web_rollup_add(&ru, WM_ALERTS_FIRED, "9", 1, T + 30);
    size_t minute = 0, hour = 0;
    for (long long now = T + 1; now <= T + 3600; now++) {
        web_rollup_add(&ru, WM_IFACE_RX, "wlan0", 100, now);
        web_rollup_close_due(&ru, now);
        size_t n;
        while ((n = web_rollup_take(&ru, q, WEB_QUEUE_ROWS)) > 0)
            for (size_t i = 0; i < n; i++) {
                if (q[i].metric != WM_ALERTS_FIRED) continue;
                if (q[i].tier == WEB_TIER_MINUTE && q[i].t == T && q[i].sum == 2)
                    minute++;
                if (q[i].tier == WEB_TIER_HOUR && q[i].t == T && q[i].sum == 2)
                    hour++;
            }
        if (now == T + 60) WT_EQ(minute, 1);
    }
    WT_EQ(minute, 1);
    WT_EQ(hour, 1);
    web_rollup_destroy(&ru);

    fresh(WEB_DEFAULT_MAX_KEYS, 1);
    web_rollup_add(&ru, WM_ALERTS_FIRED, "7", 1, T);
    char k[16];
    for (long long now = T + 1; now <= T + 600; now++) {
        for (int c = 1; c <= 127; c++) {
            snprintf(k, sizeof(k), "6g%d", c);
            web_rollup_add(&ru, WM_WIFI_AP_COUNT, k, 1, now);
        }
        web_rollup_add(&ru, WM_IFACE_RX, "wlan0", 100, now);
        web_rollup_close_due(&ru, now);
        web_rollup_take(&ru, q, WEB_QUEUE_ROWS);
    }
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.keys[WEB_KC_ALERT], 1);
    WT_EQ(st.evictions[WEB_KC_ALERT], 0);
    WT_EQ(st.evictions[WEB_KC_IFACE], 0);
    WT_EQ(st.churn_dropped, 0);
    WT_EQ(st.q_dropped, 0);
    web_rollup_destroy(&ru);
}

/* The queued rows of tier at bucket t, the queue drained. */
static size_t drain_count(int tier, long long t) {
    size_t n, hit = 0;
    while ((n = web_rollup_take(&ru, q, WEB_QUEUE_ROWS)) > 0)
        for (size_t i = 0; i < n; i++)
            if (q[i].tier == tier && q[i].t == t) hit++;
    return hit;
}

/* One sample of every metric for every key its class can hold at
 * --web-max-keys 8192; *series gets how many that is. */
static void sample_every_key(long long now, size_t *series) {
    char k[WEB_KEY_MAX + 1];
    size_t n = 0;
    for (int m = 0; m < WM_COUNT; m++) {
        int kc = web_metric_defs[m].kclass;
        int cap = kc == WEB_KC_GLOBAL ? 1 : kc == WEB_KC_DEV ? WEB_MAX_KEYS_MAX
                : kc == WEB_KC_HOST ? WEB_MAX_KEYS_MAX / 2
                : kc == WEB_KC_IFACE ? WEB_IFACE_KEYS
                : kc == WEB_KC_CHANNEL ? WEB_CHANNEL_KEYS : WEB_ALERT_KEYS;
        for (int i = 0; i < cap; i++) {
            switch (kc) {
            case WEB_KC_GLOBAL:  k[0] = '\0'; break;
            case WEB_KC_DEV:     snprintf(k, sizeof(k), "02:00:00:00:%02x:%02x",
                                          i >> 8, i & 0xff); break;
            case WEB_KC_HOST:    snprintf(k, sizeof(k), "10.0.%d.%d", i >> 8,
                                          i & 0xff); break;
            case WEB_KC_IFACE:   snprintf(k, sizeof(k), "eth%d", i); break;
            default:             snprintf(k, sizeof(k), "%d", i + 1); break;
            }
            web_rollup_add(&ru, m, k, 1, now);
            n++;
        }
    }
    *series = n;
}

/* Every key of every class at --web-max-keys 8192, each series given a
 * sample every 5 s from T-65 to T+5 (T a whole hour), the store thread
 * closing due buckets at each and draining the queue every 10 s: the
 * hour boundary closes a fine, a minute and an hour bucket of every
 * series in one pass, and close_all() then closes three more of each.
 * Neither drops a row. Seen red with the queue's cap back at the fixed
 * WEB_QUEUE_ROWS: 511,124 rows dropped by T+5, 16,384 of
 * the 74,050 minute rows kept and as many hour rows, and 16,384 of
 * close_all()'s 74,050 hour rows. */
static void test_queue_holds_max_keys_hour_and_shutdown(void) {
    fresh(WEB_MAX_KEYS_MAX, 1);
    const long long T = 1792627200;
    size_t series = 0, minute_rows = 0, hour_rows = 0;
    for (long long now = T - 65; now <= T + 5; now += 5) {
        sample_every_key(now, &series);
        web_rollup_close_due(&ru, now);
        if ((now % 10 + 10) % 10 == 5) {
            size_t n;
            while ((n = web_rollup_take(&ru, q, WEB_QUEUE_ROWS)) > 0)
                for (size_t i = 0; i < n; i++) {
                    if (q[i].tier == WEB_TIER_MINUTE && q[i].t == T - 60) minute_rows++;
                    if (q[i].tier == WEB_TIER_HOUR && q[i].t == T - 3600) hour_rows++;
                }
        }
    }
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.series, series);
    WT_EQ(st.q_dropped, 0);
    WT_EQ(minute_rows, series);
    WT_EQ(hour_rows, series);
    web_rollup_close_all(&ru);
    web_rollup_stats(&ru, &st);
    WT_EQ(st.q_dropped, 0);
    WT_EQ(drain_count(WEB_TIER_HOUR, T), series);
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
    WT_RUN(test_queue_full_drops_fine_first_and_counts);
    WT_RUN(test_queue_ring_wraps_in_order);
    WT_RUN(test_queue_ring_drops_fine_first_across_wrap);
    WT_RUN(test_recurring_host_under_lru_keeps_long_tiers);
    WT_RUN(test_churn_cannot_displace_established_ghost);
    WT_RUN(test_ghost_table_keeps_established_ways);
    WT_RUN(test_label_keys_established_and_separate);
    WT_RUN(test_queue_holds_max_keys_hour_and_shutdown);
    WT_RUN(test_catalogue);
}
