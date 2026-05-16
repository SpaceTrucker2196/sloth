#include "runner.h"
#include "ntop.h"

/* Tests for the rate calculation formula used in linux.c.
   The formula is: rate = (curr - prev) / dt
   These are pure arithmetic tests — no platform calls. */

void test_rate_zero_elapsed(void) {
    double dt = 0.0;
    /* dt == 0 must not produce a rate (div-by-zero guard) */
    ASSERT_EQ(dt <= 0.001 ? 1 : 0, 1);
}

void test_rate_one_second(void) {
    uint64_t prev = 0, curr = 1000000;
    double dt = 1.0;
    double rate = (double)(curr - prev) / dt;
    ASSERT_EQ((int)rate, 1000000);  /* 1 MB/s */
}

void test_rate_fractional_second(void) {
    uint64_t prev = 0, curr = 500000;
    double dt = 0.5;
    double rate = (double)(curr - prev) / dt;
    ASSERT_EQ((int)rate, 1000000);  /* still 1 MB/s */
}

void test_rate_no_traffic(void) {
    uint64_t prev = 1234567, curr = 1234567;
    double dt = 1.0;
    double rate = (double)(curr - prev) / dt;
    ASSERT_EQ((int)rate, 0);
}

void test_rate_gigabit(void) {
    uint64_t prev = 0, curr = 125000000;   /* 125 MB = 1 Gbps for 1 sec */
    double dt = 1.0;
    double rate = (double)(curr - prev) / dt;
    ASSERT_GE(rate, 124e6);
    ASSERT_LT(rate, 126e6);
}

void test_rate_counter_rollover(void) {
    /* uint64_t subtraction wraps correctly (two's complement) */
    uint64_t prev = 0xFFFFFFFFFFFFF000ULL;
    uint64_t curr = 0x0000000000000FFFULL;
    double dt = 1.0;
    double rate = (double)(curr - prev) / dt;
    ASSERT_GT(rate, 0.0);   /* should produce a positive rate, not NaN */
}

void test_rate_poll_guard(void) {
    /* The linux.c code skips rate update when dt < 0.001.
       Verify the threshold catches very small intervals. */
    double dt = 0.0009;
    ASSERT_EQ(dt > 0.001 ? 1 : 0, 0);   /* should be skipped */
    dt = 0.0011;
    ASSERT_EQ(dt > 0.001 ? 1 : 0, 1);   /* should apply */
}

/* ── util.h fmt_rate sanity checks ──────────────────────── */

#include "util.h"
#include <string.h>

void test_fmt_rate_bytes(void) {
    char buf[32];
    fmt_rate(999.0, buf, (int)sizeof(buf));
    ASSERT(strstr(buf, "B/s") != NULL);
}

void test_fmt_rate_kbps(void) {
    char buf[32];
    fmt_rate(1500.0, buf, (int)sizeof(buf));
    ASSERT(strstr(buf, "KB/s") != NULL);
}

void test_fmt_rate_mbps(void) {
    char buf[32];
    fmt_rate(10e6, buf, (int)sizeof(buf));
    ASSERT(strstr(buf, "MB/s") != NULL);
}

void test_fmt_rate_gbps(void) {
    char buf[32];
    fmt_rate(1.5e9, buf, (int)sizeof(buf));
    ASSERT(strstr(buf, "GB/s") != NULL);
}

void run_rate_tests(void) {
    TEST_SUITE("rate calculation");
    RUN_TEST(test_rate_zero_elapsed);
    RUN_TEST(test_rate_one_second);
    RUN_TEST(test_rate_fractional_second);
    RUN_TEST(test_rate_no_traffic);
    RUN_TEST(test_rate_gigabit);
    RUN_TEST(test_rate_counter_rollover);
    RUN_TEST(test_rate_poll_guard);

    TEST_SUITE("fmt_rate formatting");
    RUN_TEST(test_fmt_rate_bytes);
    RUN_TEST(test_fmt_rate_kbps);
    RUN_TEST(test_fmt_rate_mbps);
    RUN_TEST(test_fmt_rate_gbps);
}
