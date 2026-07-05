#include "runner.h"
#include "auth_track.h"
#include <stdint.h>
#include <string.h>

static void test_auth_flood_detects_burst(void) {
    auth_clear();
    uint8_t ap[6] = { 0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33 };
    for (int i = 0; i < 35; i++) auth_observe(ap, 1000);
    uint8_t out[6];
    int n = auth_flood_bssid(1000, 5, 30, out);
    ASSERT(n >= 30);
    ASSERT_EQ(memcmp(out, ap, 6), 0);
}

static void test_auth_flood_below_threshold(void) {
    auth_clear();
    uint8_t ap[6] = { 0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33 };
    for (int i = 0; i < 10; i++) auth_observe(ap, 1000);
    uint8_t out[6];
    ASSERT_EQ(auth_flood_bssid(1000, 5, 30, out), 0);
}

/* Frames outside the window don't count. */
static void test_auth_flood_window_ages_out(void) {
    auth_clear();
    uint8_t ap[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };
    for (int i = 0; i < 35; i++) auth_observe(ap, 1000);
    uint8_t out[6];
    ASSERT_EQ(auth_flood_bssid(1020, 5, 30, out), 0);   /* 20s later */
}

/* A flood at one AP doesn't implicate a quiet neighbour. */
static void test_auth_flood_isolates_per_bssid(void) {
    auth_clear();
    uint8_t a[6] = { 0x02, 0, 0, 0, 0, 0x01 };
    uint8_t b[6] = { 0x02, 0, 0, 0, 0, 0x02 };
    for (int i = 0; i < 35; i++) auth_observe(a, 500);
    for (int i = 0; i < 5;  i++) auth_observe(b, 500);
    uint8_t out[6];
    int n = auth_flood_bssid(500, 5, 30, out);
    ASSERT(n >= 30);
    ASSERT_EQ(memcmp(out, a, 6), 0);
}

void run_auth_track_tests(void) {
    TEST_SUITE("auth-frame flood tracker");
    RUN_TEST(test_auth_flood_detects_burst);
    RUN_TEST(test_auth_flood_below_threshold);
    RUN_TEST(test_auth_flood_window_ages_out);
    RUN_TEST(test_auth_flood_isolates_per_bssid);
}
