/* The baseline engine (#161, M3) in isolation: no store, no rollup, no
 * clock — cells fed and scored at hand-picked seconds. */
#include <math.h>
#include <stdio.h>

#include "web_baseline.h"
#include "wtest.h"

#define HOUR 3600LL
#define WEEK (168LL * HOUR)

static void test_cell_index_wraps_weekly(void) {
    long long t0 = 1792627200; /* an arbitrary hour boundary */
    int i0 = web_bl_cell_index(t0);
    WT_ASSERT(i0 >= 0 && i0 < WEB_BL_CELLS);
    WT_EQ(web_bl_cell_index(t0 + WEEK), i0);
    WT_EQ(web_bl_cell_index(t0 + 3 * WEEK), i0);
    WT_EQ(web_bl_cell_index(t0 + HOUR), (i0 + 1) % WEB_BL_CELLS);
    /* A full week apart is the same cell for every hour in it, not
     * just the one picked above. */
    for (int h = 0; h < WEB_BL_CELLS; h++)
        WT_EQ(web_bl_cell_index(t0 + h * HOUR),
             web_bl_cell_index(t0 + h * HOUR + WEEK));
}

static void test_never_fed_scores_absent(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 8), 0);
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&b, WM_HOST_RX, "10.0.0.1", 0, 1.0, &sc), -1);
    web_baseline_destroy(&b);
}

/* Fewer than WEB_BL_WARM_N feeds: warming, z forced to 0 even though
 * the value fed is wildly off the one mean sample so far. Mutating the
 * warming check away (always scoring) would make this fail, because
 * the single prior sample of 1.0 against a probe of 1000.0 is a huge
 * z — the test is live, not vacuously true. */
static void test_warming_blocks_a_score(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 8), 0);
    long long t0 = 1792627200;
    web_baseline_feed(&b, WM_HOST_RX, "10.0.0.1", t0, 1.0);
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&b, WM_HOST_RX, "10.0.0.1", t0, 1000.0, &sc), 0);
    WT_ASSERT(sc.warming);
    WT_EQ(sc.n, 1);
    WT_ASSERT(sc.z == 0.0);
    web_baseline_destroy(&b);
}

/* WEB_BL_WARM_N identical feeds: no longer warming, a probe at the
 * same value scores z near 0, and a wildly different probe scores a
 * large z. */
static void test_established_cell_scores_z(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 8), 0);
    long long t0 = 1792627200;
    for (int i = 0; i < WEB_BL_WARM_N; i++)
        web_baseline_feed(&b, WM_HOST_RX, "10.0.0.1", t0 + i * WEEK, 10.0);
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&b, WM_HOST_RX, "10.0.0.1", t0, 10.0, &sc), 0);
    WT_ASSERT(!sc.warming);
    WT_EQ(sc.n, WEB_BL_WARM_N);
    WT_ASSERT(fabs(sc.z) < 0.5);
    WT_EQ(web_baseline_score(&b, WM_HOST_RX, "10.0.0.1", t0, 1000.0, &sc), 0);
    WT_ASSERT(fabs(sc.z) > 10.0);
    web_baseline_destroy(&b);
}

/* A different hour-of-week cell of the same (metric, key) is its own
 * story: feeding one does not warm or move the other. */
static void test_cells_are_independent(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 8), 0);
    long long t0 = 1792627200;
    long long t_night = t0, t_day = t0 + 12 * HOUR;
    for (int i = 0; i < WEB_BL_WARM_N; i++)
        web_baseline_feed(&b, WM_DEV_PRESENT, "aa:bb", t_night + i * WEEK, 1.0);
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&b, WM_DEV_PRESENT, "aa:bb", t_night, 1.0, &sc),
         0);
    WT_ASSERT(!sc.warming);
    WT_EQ(web_baseline_score(&b, WM_DEV_PRESENT, "aa:bb", t_day, 1.0, &sc),
         0);
    WT_ASSERT(sc.warming);   /* t_day's cell has never been fed */
    WT_EQ(sc.n, 0);
    web_baseline_destroy(&b);
}

/* A full table evicts the least-recently-fed (metric, key), never one
 * still in use. Mutating lru_victim() to pick the newest instead would
 * evict "b" here and leave "a" findable — caught by this test. */
static void test_full_table_evicts_lru(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 2), 0);
    long long t0 = 1792627200;
    web_baseline_feed(&b, WM_HOST_RX, "a", t0, 1.0);
    web_baseline_feed(&b, WM_HOST_RX, "b", t0 + 1, 1.0);
    WT_EQ(web_baseline_count(&b), 2);
    WT_EQ(web_baseline_evictions(&b), 0UL);
    /* A third key, fed later than both: "a" (older last_seen) goes. */
    web_baseline_feed(&b, WM_HOST_RX, "c", t0 + 2, 1.0);
    WT_EQ(web_baseline_count(&b), 2);
    WT_EQ(web_baseline_evictions(&b), 1UL);
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&b, WM_HOST_RX, "a", t0, 1.0, &sc), -1);
    WT_EQ(web_baseline_score(&b, WM_HOST_RX, "b", t0, 1.0, &sc), 0);
    WT_EQ(web_baseline_score(&b, WM_HOST_RX, "c", t0, 1.0, &sc), 0);
    web_baseline_destroy(&b);
}

/* Re-feeding the same (metric, key) does not grow the table or re-use
 * another entry's slot. */
static void test_refeed_same_key_no_growth(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 4), 0);
    long long t0 = 1792627200;
    for (int i = 0; i < 10; i++)
        web_baseline_feed(&b, WM_HOST_RX, "10.0.0.1", t0 + i * WEEK, 1.0);
    WT_EQ(web_baseline_count(&b), 1);
    WT_EQ(web_baseline_evictions(&b), 0UL);
    web_baseline_destroy(&b);
}

/* The two metrics most anomaly rules scan (the dev and host classes at
 * default cardinality) fit well under the derived cap, so the formula
 * is not off by an order of magnitude in either direction. */
static void test_cap_for_is_sane(void) {
    int cap = web_baseline_cap_for(WEB_DEFAULT_MAX_KEYS);
    WT_ASSERT(cap > WEB_DEFAULT_MAX_KEYS);
    WT_ASSERT(cap < WEB_DEFAULT_MAX_KEYS * 20);
    WT_ASSERT(web_baseline_cap_for(WEB_MAX_KEYS_MIN) > 0);
    WT_ASSERT(web_baseline_cap_for(WEB_MAX_KEYS_MAX) > 0);
}

static void test_nan_and_inf_feed_ignored(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 4), 0);
    long long t0 = 1792627200;
    web_baseline_feed(&b, WM_HOST_RX, "10.0.0.1", t0, 1.0 / 0.0 - 1.0 / 0.0);
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&b, WM_HOST_RX, "10.0.0.1", t0, 1.0, &sc), -1);
    web_baseline_destroy(&b);
}

void run_baseline_tests(void) {
    WT_RUN(test_cell_index_wraps_weekly);
    WT_RUN(test_never_fed_scores_absent);
    WT_RUN(test_warming_blocks_a_score);
    WT_RUN(test_established_cell_scores_z);
    WT_RUN(test_cells_are_independent);
    WT_RUN(test_full_table_evicts_lru);
    WT_RUN(test_refeed_same_key_no_growth);
    WT_RUN(test_cap_for_is_sane);
    WT_RUN(test_nan_and_inf_feed_ignored);
}
