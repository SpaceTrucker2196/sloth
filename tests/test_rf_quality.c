/* Per-channel RF quality accounting (roadmap B3).
 *
 * Every timestamp is supplied, so windowing is exercised across minutes
 * without waiting for any. */

#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "rf_quality.h"

#define T0 1700000000L

/* Feed `n` frames, of which `retries` carry the retry bit. */
static void feed(int ch, int n, int retries, int badfcs, time_t at) {
    for (int i = 0; i < n; i++)
        rf_quality_observe(ch, i < retries, i < badfcs, at);
}

/* ── ratios ──────────────────────────────────────────────── */

static void test_retry_ratio(void) {
    rf_quality_clear();
    feed(6, 200, 50, 0, T0);              /* 25% retries */
    ASSERT_EQ(rf_quality_retry_pct(6, T0), 25);
    ASSERT_EQ(rf_quality_badfcs_pct(6, T0), 0);
}

static void test_badfcs_ratio(void) {
    rf_quality_clear();
    feed(36, 400, 0, 40, T0);             /* 10% bad FCS */
    ASSERT_EQ(rf_quality_badfcs_pct(36, T0), 10);
}

/* Below the sample floor the answer is "don't know" (-1), which is a
 * different answer from 0% — one retried frame out of three is 33% and
 * means nothing. Conflating the two would let a single frame paint a
 * channel as degraded. */
static void test_below_sample_floor_is_unknown_not_zero(void) {
    rf_quality_clear();
    feed(11, 3, 1, 0, T0);
    ASSERT_EQ(rf_quality_retry_pct(11, T0), -1);
    ASSERT_NE(rf_quality_retry_pct(11, T0), 33);
    ASSERT_EQ(rf_quality_is_degraded(11, T0), 0);

    /* Exactly at the floor it becomes a measurement. */
    rf_quality_clear();
    feed(11, RF_MIN_FRAMES, RF_MIN_FRAMES, 0, T0);
    ASSERT_EQ(rf_quality_retry_pct(11, T0), 100);
}

static void test_unknown_channel_is_unknown(void) {
    rf_quality_clear();
    ASSERT_EQ(rf_quality_retry_pct(6, T0), -1);
    ASSERT_EQ(rf_quality_badfcs_pct(6, T0), -1);
    ASSERT_EQ(rf_quality_is_degraded(6, T0), 0);
}

/* Channel 0 is an unmapped frequency, not a channel — counting it would
 * pool every 6 GHz frame from a driver we cannot map into one bogus row. */
static void test_channel_zero_is_ignored(void) {
    rf_quality_clear();
    feed(0, 500, 400, 0, T0);
    ASSERT_EQ(rf_quality_retry_pct(0, T0), -1);
}

/* ── degradation ─────────────────────────────────────────── */

static void test_degraded_threshold(void) {
    rf_quality_clear();
    feed(1, 200, 78, 0, T0);              /* 39% — under */
    ASSERT_EQ(rf_quality_is_degraded(1, T0), 0);

    rf_quality_clear();
    feed(1, 200, 80, 0, T0);              /* 40% — at the threshold */
    ASSERT_EQ(rf_quality_retry_pct(1, T0), RF_RETRY_DEGRADED_PCT);
    ASSERT_EQ(rf_quality_is_degraded(1, T0), 1);
}

/* A quiet channel is not a clean one: no traffic must never read as
 * healthy-and-measured. */
static void test_quiet_channel_is_not_degraded_but_is_unknown(void) {
    rf_quality_clear();
    feed(44, 10, 10, 0, T0);              /* 100% retries, tiny sample */
    ASSERT_EQ(rf_quality_is_degraded(44, T0), 0);
    ASSERT_EQ(rf_quality_retry_pct(44, T0), -1);
}

/* ── windowing ───────────────────────────────────────────── */

/* A channel that was bad and recovered must stop reading as degraded —
 * counters reset rather than decay, so the operator sees the channel as
 * it is now, not a weighted memory of an hour ago. */
static void test_window_rolls_and_clears_history(void) {
    rf_quality_clear();
    feed(6, 200, 160, 0, T0);
    ASSERT_EQ(rf_quality_is_degraded(6, T0), 1);

    /* Well past the window, with clean traffic. */
    time_t later = T0 + RF_WINDOW_SECS + 60;
    feed(6, 200, 0, 0, later);
    ASSERT_EQ(rf_quality_retry_pct(6, later), 0);
    ASSERT_EQ(rf_quality_is_degraded(6, later), 0);
}

/* Reading the ratio after the window has expired, with no new traffic,
 * must not report the stale figure. */
static void test_stale_window_read_reports_unknown(void) {
    rf_quality_clear();
    feed(6, 200, 160, 0, T0);
    ASSERT_EQ(rf_quality_is_degraded(6, T0), 1);
    ASSERT_EQ(rf_quality_retry_pct(6, T0 + RF_WINDOW_SECS + 60), -1);
}

static void test_backwards_clock_is_safe(void) {
    rf_quality_clear();
    feed(6, 200, 100, 0, T0);
    ASSERT_EQ(rf_quality_retry_pct(6, T0 - 10000), 50);
}

/* ── channels are independent ────────────────────────────── */

static void test_channels_tracked_separately(void) {
    rf_quality_clear();
    feed(1,  200, 180, 0, T0);
    feed(11, 200,   4, 0, T0);
    ASSERT_EQ(rf_quality_is_degraded(1,  T0), 1);
    ASSERT_EQ(rf_quality_is_degraded(11, T0), 0);
    ASSERT_EQ(rf_quality_retry_pct(11, T0), 2);
}

/* A hop list longer than the table must not lock out the channel the
 * radio is on right now. */
static void test_table_full_evicts_stalest(void) {
    rf_quality_clear();
    for (int i = 1; i <= MAX_RF_CHANNELS; i++)
        feed(i, 1, 0, 0, T0);
    /* A new channel arrives later than everything else. */
    feed(999, RF_MIN_FRAMES, RF_MIN_FRAMES, 0, T0 + 10);
    ASSERT_EQ(rf_quality_retry_pct(999, T0 + 10), 100);
}

/* ── snapshot into the channel view ──────────────────────── */

static void test_snapshot_annotates_existing_rows(void) {
    rf_quality_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.channels[0].channel = 6;
    s.channels[1].channel = 36;
    s.channel_count = 2;

    feed(6, 200, 100, 20, T0);
    rf_quality_snapshot(&s, T0);

    ASSERT_EQ((int)s.channels[0].frames, 200);
    ASSERT_EQ(s.channels[0].retry_pct, 50);
    ASSERT_EQ(s.channels[0].badfcs_pct, 10);
    /* Channel 36 had no traffic — unknown, not zero. */
    ASSERT_EQ((int)s.channels[1].frames, 0);
    ASSERT_EQ(s.channels[1].retry_pct, -1);
}

/* The snapshot annotates; it must not invent rows for channels the
 * beacon table never saw, or the view would grow entries with no AP. */
static void test_snapshot_creates_no_rows(void) {
    rf_quality_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    feed(6, 200, 100, 0, T0);
    rf_quality_snapshot(&s, T0);
    ASSERT_EQ(s.channel_count, 0);
}

static void test_snapshot_null_state_is_safe(void) {
    rf_quality_clear();
    rf_quality_snapshot(NULL, T0);
    ASSERT_EQ(rf_quality_retry_pct(6, T0), -1);
}

static void test_clear_empties_everything(void) {
    rf_quality_clear();
    feed(6, 200, 100, 0, T0);
    ASSERT_EQ(rf_quality_retry_pct(6, T0), 50);
    rf_quality_clear();
    ASSERT_EQ(rf_quality_retry_pct(6, T0), -1);
}

void run_rf_quality_tests(void) {
    TEST_SUITE("rf quality: ratios");
    RUN_TEST(test_retry_ratio);
    RUN_TEST(test_badfcs_ratio);
    RUN_TEST(test_below_sample_floor_is_unknown_not_zero);
    RUN_TEST(test_unknown_channel_is_unknown);
    RUN_TEST(test_channel_zero_is_ignored);

    TEST_SUITE("rf quality: degradation");
    RUN_TEST(test_degraded_threshold);
    RUN_TEST(test_quiet_channel_is_not_degraded_but_is_unknown);

    TEST_SUITE("rf quality: windowing");
    RUN_TEST(test_window_rolls_and_clears_history);
    RUN_TEST(test_stale_window_read_reports_unknown);
    RUN_TEST(test_backwards_clock_is_safe);

    TEST_SUITE("rf quality: channel independence");
    RUN_TEST(test_channels_tracked_separately);
    RUN_TEST(test_table_full_evicts_stalest);

    TEST_SUITE("rf quality: snapshot");
    RUN_TEST(test_snapshot_annotates_existing_rows);
    RUN_TEST(test_snapshot_creates_no_rows);
    RUN_TEST(test_snapshot_null_state_is_safe);
    RUN_TEST(test_clear_empties_everything);
}
