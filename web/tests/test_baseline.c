/* The baseline engine (#161, M3) in isolation: no store, no rollup, no
 * clock; cells fed and scored at hand-picked seconds. The suite runs
 * with TZ pinned to UTC (web_test_main.c); the DST test sets its own
 * zone and puts UTC back. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "web_baseline.h"
#include "wtest.h"

#define HOUR 3600LL
#define WEEK (168LL * HOUR)
#define MON0 1792368000LL     /* Monday 2026-10-19 00:00 UTC */
#define THU0 1792627200LL     /* Thursday 2026-10-22 00:00 UTC */

/* The cell is the local hour of the week, Monday 00:00 first. */
static void test_cell_index_is_local_hour_of_week(void) {
    WT_EQ(web_bl_cell_index(MON0), 0);
    WT_EQ(web_bl_cell_index(MON0 + 14 * HOUR + 59 * 60), 14);
    WT_EQ(web_bl_cell_index(THU0), 3 * 24);
    WT_EQ(web_bl_cell_index(MON0 + WEEK - 1), WEB_BL_CELLS - 1);
    for (int h = 0; h < WEB_BL_CELLS; h++) {
        WT_EQ(web_bl_cell_index(MON0 + h * HOUR), h);
        WT_EQ(web_bl_cell_index(MON0 + h * HOUR + 3 * WEEK), h);
    }
}

/* Across a daylight-saving change the same local hour stays in the same
 * cell, though it is 167 UTC hours later, not 168. An index of UTC
 * hours (the previous slice's) puts the second Monday 22:00 in cell 21
 * and is red here. */
static void test_cell_index_follows_dst(void) {
    setenv("TZ", "EST5EDT,M3.2.0,M11.1.0", 1);
    tzset();
    long long before = 1804561200LL;   /* Mon 2027-03-08 22:00 EST */
    long long after = 1805162400LL;    /* Mon 2027-03-15 22:00 EDT */
    WT_EQ(after - before, 167 * HOUR);
    WT_EQ(web_bl_cell_index(before), 22);
    WT_EQ(web_bl_cell_index(after), 22);
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 8), 0);
    for (int i = 0; i < 4; i++)
        web_baseline_feed(&b, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:01",
                          before - (3 - i) * WEEK, 1.0, 1);
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&b, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:01", after,
                             1.0, &sc), 0);
    WT_EQ(sc.n, 4);
    WT_ASSERT(sc.mean > 0.99);
    web_baseline_destroy(&b);
    setenv("TZ", "UTC0", 1);
    tzset();
}

/* "No entry from a zero feed" seen red with the !real test removed. */
static void test_never_fed_scores_absent(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 8), 0);
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&b, WM_HOST_RX, "10.0.0.1", 0, 1.0, &sc), -1);
    /* A zero feed does not make an entry: only a real row does. */
    WT_EQ(web_baseline_feed(&b, WM_DNS_QUERIES, "10.0.0.1", THU0, 0.0, 0), -1);
    WT_EQ(web_baseline_count(&b), 0);
    web_baseline_destroy(&b);
}

/* Fewer than WEB_BL_WARM_N feeds: warming, z forced to 0 although the
 * probe is far off the one sample. */
static void test_warming_blocks_a_score(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 8), 0);
    web_baseline_feed(&b, WM_HOST_RX, "10.0.0.1", THU0, 1.0, 1);
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&b, WM_HOST_RX, "10.0.0.1", THU0, 1e7, &sc), 0);
    WT_ASSERT(sc.warming);
    WT_EQ(sc.n, 1);
    WT_ASSERT(sc.z == 0.0);
    web_baseline_destroy(&b);
}

static void test_established_cell_scores_z(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 8), 0);
    for (int i = 0; i < WEB_BL_WARM_N; i++)
        web_baseline_feed(&b, WM_HOST_RX, "10.0.0.1", THU0 + i * WEEK, 10000.0, 1);
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&b, WM_HOST_RX, "10.0.0.1", THU0, 10000.0, &sc), 0);
    WT_ASSERT(!sc.warming);
    WT_EQ(sc.n, WEB_BL_WARM_N);
    WT_ASSERT(fabs(sc.z) < 0.5);
    WT_EQ(web_baseline_score(&b, WM_HOST_RX, "10.0.0.1", THU0, 1e6, &sc), 0);
    WT_ASSERT(fabs(sc.z) > 10.0);
    web_baseline_destroy(&b);
}

/* The audit's case: three equal weeks give var 0, and with sd =
 * sqrt(var + 1e-9) one AP more on the channel scored z = 31,623. The sd
 * is floored at one unit (one AP), so it scores 1. Seen red with the
 * floor removed (sd = sqrt(var)): z became infinite. */
static void test_constant_history_one_unit_is_not_out_of_band(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 8), 0);
    for (int i = 0; i < 3; i++)
        web_baseline_feed(&b, WM_WIFI_AP_COUNT, "6", THU0 + i * WEEK, 5.0, 1);
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&b, WM_WIFI_AP_COUNT, "6", THU0, 6.0, &sc), 0);
    WT_ASSERT(!sc.warming);
    WT_ASSERT(sc.sd >= 1.0);
    WT_ASSERT(fabs(sc.z) <= 1.0 + 1e-9);
    /* The floor is also a share of the mean: 10% of 400 conns is 40. */
    for (int i = 0; i < 3; i++)
        web_baseline_feed(&b, WM_CONNS_TOTAL, "", THU0 + i * WEEK, 400.0, 1);
    WT_EQ(web_baseline_score(&b, WM_CONNS_TOTAL, "", THU0, 440.0, &sc), 0);
    WT_ASSERT(fabs(sc.sd - 40.0) < 1e-6);
    WT_ASSERT(fabs(sc.z - 1.0) < 1e-6);
    /* And a byte rate's unit is 1 KiB/s. */
    WT_ASSERT(web_bl_sd_floor(WM_HOST_RX, 0.0) == 1024.0);
    WT_ASSERT(web_bl_sd_floor(WM_DNS_QUERIES, 0.0) == 1.0);
    web_baseline_destroy(&b);
}

/* One hour is fed once: a second feed of the same hour (a late row, a
 * zero feed after a real one) is ignored. Seen red with the last_fed
 * guard removed. */
static void test_an_hour_is_fed_once(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 8), 0);
    WT_EQ(web_baseline_feed(&b, WM_DNS_QUERIES, "10.0.0.1", THU0, 4.0, 1), 0);
    WT_EQ(web_baseline_feed(&b, WM_DNS_QUERIES, "10.0.0.1", THU0, 9.0, 1), -1);
    WT_EQ(web_baseline_zero_missing(&b, THU0), 0);
    web_bl_cell_t c[WEB_BL_CELLS];
    WT_EQ(web_baseline_cells(&b, WM_DNS_QUERIES, "10.0.0.1", c), 0);
    WT_EQ(c[web_bl_cell_index(THU0)].n, 1);
    WT_ASSERT(c[web_bl_cell_index(THU0)].mean == 4.0f);
    web_baseline_destroy(&b);
}

/* An hour with no row is 0 for a counter and for presence, and not a
 * sample at all for a gauge (not measured is not zero). The gauge seen
 * red with gauges zero-fed too. */
static void test_zero_missing_feeds_counters_and_presence_only(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 8), 0);
    web_baseline_feed(&b, WM_DNS_QUERIES, "10.0.0.1", THU0, 4.0, 1);
    web_baseline_feed(&b, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:01", THU0, 1.0, 1);
    web_baseline_feed(&b, WM_HOST_CONNS, "10.0.0.1", THU0, 5.0, 1);
    WT_EQ(web_baseline_zero_missing(&b, THU0 + HOUR), 2);
    web_bl_cell_t c[WEB_BL_CELLS];
    int ci = web_bl_cell_index(THU0 + HOUR);
    WT_EQ(web_baseline_cells(&b, WM_DNS_QUERIES, "10.0.0.1", c), 0);
    WT_EQ(c[ci].n, 1);
    WT_ASSERT(c[ci].mean == 0.0f);
    WT_EQ(web_baseline_cells(&b, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:01", c), 0);
    WT_EQ(c[ci].n, 1);
    WT_EQ(web_baseline_cells(&b, WM_HOST_CONNS, "10.0.0.1", c), 0);
    WT_EQ(c[ci].n, 0);
    /* A zero feed is not activity: last_active stays where the row was. */
    web_bl_rec_t r[8];
    int n = web_baseline_take_dirty(&b, r, 8);
    WT_ASSERT(n >= 3);
    for (int i = 0; i < n; i++) WT_EQ(r[i].last_active, THU0);
    web_baseline_destroy(&b);
}

static void test_cells_are_independent(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 8), 0);
    long long t_night = THU0, t_day = THU0 + 12 * HOUR;
    for (int i = 0; i < WEB_BL_WARM_N; i++)
        web_baseline_feed(&b, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:02",
                          t_night + i * WEEK, 1.0, 1);
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&b, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:02", t_night,
                             1.0, &sc), 0);
    WT_ASSERT(!sc.warming);
    WT_EQ(web_baseline_score(&b, WM_DEV_PRESENT, "aa:bb:cc:dd:ee:02", t_day,
                             1.0, &sc), 0);
    WT_ASSERT(sc.warming);
    WT_EQ(sc.n, 0);
    web_baseline_destroy(&b);
}

/* A full table evicts the least recently active entry, by real feeds:
 * 10.0.0.1 was fed a zero later than 10.0.0.2's row, and still goes
 * first. Seen red with the eviction taking the LRU list's head (the
 * most recently active) instead of its tail. */
static void test_full_table_evicts_least_recently_active(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 2), 0);
    web_baseline_feed(&b, WM_DNS_QUERIES, "10.0.0.1", THU0, 1.0, 1);
    web_baseline_feed(&b, WM_DNS_QUERIES, "10.0.0.2", THU0 + HOUR, 1.0, 1);
    web_baseline_zero_missing(&b, THU0 + 2 * HOUR);
    WT_EQ(web_baseline_evictions(&b), 0UL);
    web_baseline_feed(&b, WM_DNS_QUERIES, "10.0.0.3", THU0 + 3 * HOUR, 1.0, 1);
    WT_EQ(web_baseline_count(&b), 2);
    WT_EQ(web_baseline_evictions(&b), 1UL);
    web_bl_score_t sc;
    WT_EQ(web_baseline_score(&b, WM_DNS_QUERIES, "10.0.0.1", THU0, 1.0, &sc), -1);
    WT_EQ(web_baseline_score(&b, WM_DNS_QUERIES, "10.0.0.2", THU0, 1.0, &sc), 0);
    WT_EQ(web_baseline_score(&b, WM_DNS_QUERIES, "10.0.0.3", THU0, 1.0, &sc), 0);
    web_baseline_destroy(&b);
}

/* Entries idle past the hour tier's retention are aged out, and their
 * row ids queued for the store to delete, once. "Once" seen red with
 * web_baseline_take_deleted() not removing what it returned. */
static void test_age_out_and_delete_queue(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 8), 0);
    web_baseline_feed(&b, WM_DNS_QUERIES, "10.0.0.1", THU0, 1.0, 1);
    web_baseline_feed(&b, WM_DNS_QUERIES, "10.0.0.2", THU0 + WEEK, 1.0, 1);
    web_baseline_set_dbid(&b, WM_DNS_QUERIES, "10.0.0.1", 41);
    WT_EQ(web_baseline_age_out(&b, THU0 + HOUR), 1);
    WT_EQ(web_baseline_count(&b), 1);
    long long ids[4];
    WT_EQ(web_baseline_take_deleted(&b, ids, 4), 1);
    WT_EQ(ids[0], 41);
    WT_EQ(web_baseline_take_deleted(&b, ids, 4), 0);
    web_baseline_destroy(&b);
}

/* Memory follows the entries there are: one entry in a table capped at
 * the largest --web-max-keys allocates one chunk. */
static void test_allocation_follows_entries(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, web_baseline_cap_for(WEB_MAX_KEYS_MAX)), 0);
    web_baseline_feed(&b, WM_DNS_QUERIES, "10.0.0.1", THU0, 1.0, 1);
    web_bl_stats_t st;
    web_baseline_stats(&b, &st);
    WT_EQ(st.entries, 1);
    WT_EQ(st.chunks, 1);
    WT_ASSERT(sizeof(web_bl_cell_t) <= 12);
    web_baseline_destroy(&b);
}

/* Dirty cells come out once, with the entry's row first; restore puts
 * them back. "Once" seen red with web_baseline_take_dirty() leaving the
 * bit set; "a restored entry is not dirty" with load_cell() marking it;
 * the invalid cell refused with load_cell()'s finite test removed. */
static void test_dirty_and_restore_round_trip(void) {
    web_baseline_t b, r;
    WT_EQ(web_baseline_init(&b, 8), 0);
    WT_EQ(web_baseline_init(&r, 8), 0);
    web_baseline_feed(&b, WM_HOST_CONNS, "10.0.0.1", THU0, 5.0, 1);
    web_baseline_feed(&b, WM_HOST_CONNS, "10.0.0.1", THU0 + WEEK, 7.0, 1);
    web_bl_rec_t rec[8];
    int n = web_baseline_take_dirty(&b, rec, 8);
    WT_EQ(n, 2);
    WT_EQ(rec[0].cell, -1);
    WT_EQ(rec[0].db_id, -1);
    WT_EQ(rec[1].cell, web_bl_cell_index(THU0));
    WT_EQ(rec[1].n, 2);
    WT_EQ(web_baseline_take_dirty(&b, rec, 8), 0);
    WT_EQ(web_baseline_load(&r, WM_HOST_CONNS, "10.0.0.1", 7, rec[0].last_active,
                            rec[0].last_fed), 0);
    WT_EQ(web_baseline_load_cell(&r, WM_HOST_CONNS, "10.0.0.1", rec[1].cell,
                                 rec[1].mean, rec[1].var, rec[1].n), 0);
    web_bl_score_t s1, s2;
    WT_EQ(web_baseline_score(&b, WM_HOST_CONNS, "10.0.0.1", THU0, 9.0, &s1), 0);
    WT_EQ(web_baseline_score(&r, WM_HOST_CONNS, "10.0.0.1", THU0, 9.0, &s2), 0);
    WT_ASSERT(s1.mean == s2.mean && s1.sd == s2.sd && s1.n == s2.n);
    /* A restored entry is not dirty, and its last feed still guards the
     * hour it covered. */
    WT_EQ(web_baseline_take_dirty(&r, rec, 8), 0);
    WT_EQ(web_baseline_feed(&r, WM_HOST_CONNS, "10.0.0.1", THU0 + WEEK, 1.0, 1), -1);
    /* Restore refuses what is not valid. */
    WT_EQ(web_baseline_load_cell(&r, WM_HOST_CONNS, "10.0.0.1", WEB_BL_CELLS,
                                 1, 0, 1), -1);
    WT_EQ(web_baseline_load_cell(&r, WM_HOST_CONNS, "10.0.0.1", 0, NAN, 0, 1), -1);
    web_baseline_destroy(&b);
    web_baseline_destroy(&r);
}

static void test_cap_for_is_sane(void) {
    int cap = web_baseline_cap_for(WEB_DEFAULT_MAX_KEYS);
    WT_ASSERT(cap > WEB_DEFAULT_MAX_KEYS);
    WT_ASSERT(cap < WEB_DEFAULT_MAX_KEYS * 20);
    WT_ASSERT(web_baseline_cap_for(WEB_MAX_KEYS_MIN) > 0);
    WT_ASSERT(web_baseline_cap_for(WEB_MAX_KEYS_MAX) > 0);
}

/* NaN and both infinities leave the pair unfed. Seen red with the
 * isfinite() check narrowed to isnan(): +Inf made an entry. */
static void test_nan_and_inf_feed_ignored(void) {
    web_baseline_t b;
    WT_EQ(web_baseline_init(&b, 4), 0);
    web_bl_score_t sc;
    WT_EQ(web_baseline_feed(&b, WM_HOST_RX, "10.0.0.1", THU0, NAN, 1), -1);
    WT_EQ(web_baseline_feed(&b, WM_HOST_RX, "10.0.0.1", THU0, INFINITY, 1), -1);
    WT_EQ(web_baseline_feed(&b, WM_HOST_RX, "10.0.0.1", THU0, -INFINITY, 1), -1);
    WT_EQ(web_baseline_score(&b, WM_HOST_RX, "10.0.0.1", THU0, 1.0, &sc), -1);
    WT_EQ(web_baseline_count(&b), 0);
    web_baseline_destroy(&b);
}

/* The scale of a bucket: a counter per minute whatever its step, a
 * gauge's mean, presence's max. */
static void test_value_scale(void) {
    web_point_t p = { 0, 120.0, 1.0, 9.0, 4 };
    WT_ASSERT(web_bl_value(WM_DNS_QUERIES, &p, 3600) == 2.0);
    WT_ASSERT(web_bl_value(WM_DNS_QUERIES, &p, 60) == 120.0);
    WT_ASSERT(web_bl_value(WM_HOST_CONNS, &p, 3600) == 30.0);
    WT_ASSERT(web_bl_value(WM_DEV_PRESENT, &p, 3600) == 9.0);
}

void run_baseline_tests(void) {
    WT_RUN(test_cell_index_is_local_hour_of_week);
    WT_RUN(test_cell_index_follows_dst);
    WT_RUN(test_never_fed_scores_absent);
    WT_RUN(test_warming_blocks_a_score);
    WT_RUN(test_established_cell_scores_z);
    WT_RUN(test_constant_history_one_unit_is_not_out_of_band);
    WT_RUN(test_an_hour_is_fed_once);
    WT_RUN(test_zero_missing_feeds_counters_and_presence_only);
    WT_RUN(test_cells_are_independent);
    WT_RUN(test_full_table_evicts_least_recently_active);
    WT_RUN(test_age_out_and_delete_queue);
    WT_RUN(test_allocation_follows_entries);
    WT_RUN(test_dirty_and_restore_round_trip);
    WT_RUN(test_cap_for_is_sane);
    WT_RUN(test_nan_and_inf_feed_ignored);
    WT_RUN(test_value_scale);
}
