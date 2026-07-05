#include "runner.h"
#include "sloth.h"
#include "wifi_merge.h"
#include <string.h>
#include <stdlib.h>

static const uint8_t AP_A[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
static const uint8_t AP_B[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

/* Single-radio compatibility: one sensor's observations merge as an
 * identity map — one entity per distinct key, seen_by == 1. */
static void test_single_radio_identity(void) {
    wifi_merge_t m; wifi_merge_reset(&m);
    wifi_merge_observe(&m, 0, AP_A, 6, 2437, -50, 100);
    wifi_merge_observe(&m, 0, AP_A, 6, 2437, -52, 110); /* same radio again */
    wifi_merge_observe(&m, 0, AP_B, 1, 2412, -60, 120);
    ASSERT_EQ(m.count, 2);
    wifi_merged_t *a = wifi_merge_find(&m, AP_A);
    ASSERT(a != NULL);
    ASSERT_EQ(a->seen_by, 1);
    ASSERT_EQ(a->sensor_mask, 0x0001);
    ASSERT_EQ((long long)a->observations, 2);
    ASSERT_EQ((long long)a->first_seen, 100);
    ASSERT_EQ((long long)a->last_seen, 110);
}

/* Two-radio merge: the same entity heard by two radios collapses to one
 * row with seen_by == 2 and both sensor bits set. */
static void test_two_radio_merge(void) {
    wifi_merge_t m; wifi_merge_reset(&m);
    wifi_merge_observe(&m, 0, AP_A, 6,  2437, -70, 100); /* radio 0, weaker */
    wifi_merge_observe(&m, 3, AP_A, 6,  2437, -40, 105); /* radio 3, stronger */
    ASSERT_EQ(m.count, 1);                    /* no duplicate row */
    wifi_merged_t *a = wifi_merge_find(&m, AP_A);
    ASSERT(a != NULL);
    ASSERT_EQ(a->seen_by, 2);
    ASSERT_EQ(a->sensor_mask, (1u<<0)|(1u<<3));
    ASSERT_EQ(a->best_rssi, -40);             /* strongest wins */
    ASSERT_EQ(a->best_sensor, 3);
    ASSERT_EQ((long long)a->observations, 2);
    ASSERT_EQ((long long)a->last_seen, 105);
}

/* Duplicate observation handling: repeated hits from an already-counted
 * radio bump recency/observations but never inflate seen_by. */
static void test_duplicate_no_inflation(void) {
    wifi_merge_t m; wifi_merge_reset(&m);
    for (int i = 0; i < 50; i++)
        wifi_merge_observe(&m, 1, AP_A, 6, 2437, -55, 200 + i);
    wifi_merged_t *a = wifi_merge_find(&m, AP_A);
    ASSERT(a != NULL);
    ASSERT_EQ(a->seen_by, 1);
    ASSERT_EQ((long long)a->observations, 50);
    ASSERT_EQ((long long)a->last_seen, 249);
}

/* Per-sensor error handling: an out-of-range sensor id is rejected and
 * counted as dropped, not merged; a NULL key likewise. */
static void test_bad_sensor_id_dropped(void) {
    wifi_merge_t m; wifi_merge_reset(&m);
    ASSERT(wifi_merge_observe(&m, -1, AP_A, 6, 2437, -50, 100) == NULL);
    ASSERT(wifi_merge_observe(&m, MAX_SENSORS, AP_A, 6, 2437, -50, 100) == NULL);
    ASSERT(wifi_merge_observe(&m, 0, NULL, 6, 2437, -50, 100) == NULL);
    ASSERT_EQ(m.count, 0);
    ASSERT_EQ((long long)m.dropped, 3);
}

/* Unknown (0) RSSI never masquerades as the strongest signal. */
static void test_zero_rssi_not_best(void) {
    wifi_merge_t m; wifi_merge_reset(&m);
    wifi_merge_observe(&m, 0, AP_A, 6, 2437, 0,   100); /* no signal sample */
    wifi_merged_t *a = wifi_merge_find(&m, AP_A);
    ASSERT_EQ(a->best_rssi, 0);
    ASSERT_EQ(a->best_sensor, -1);
    wifi_merge_observe(&m, 0, AP_A, 6, 2437, -80, 110); /* real sample */
    ASSERT_EQ(a->best_rssi, -80);
    ASSERT_EQ(a->best_sensor, 0);
}

/* Table-full is bounded and counted, not an overflow. */
static void test_table_full_bounded(void) {
    wifi_merge_t m; wifi_merge_reset(&m);
    uint8_t k[6] = {0};
    for (int i = 0; i < MAX_WIFI_MERGED + 8; i++) {
        k[5] = (uint8_t)(i & 0xFF);
        k[4] = (uint8_t)((i >> 8) & 0xFF);
        wifi_merge_observe(&m, 0, k, 1, 2412, -50, 300);
    }
    ASSERT_EQ(m.count, MAX_WIFI_MERGED);
    ASSERT_EQ((long long)m.dropped, 8);
}

/* The beacon-table bridge tags every AP with the given sensor id. */
static void test_from_beacons_bridge(void) {
    sloth_state_t *s = calloc(1, sizeof(*s));
    ASSERT(s != NULL);
    memcpy(s->beacon_aps[0].bssid, AP_A, 6);
    s->beacon_aps[0].channel = 6; s->beacon_aps[0].signal_dbm = -45;
    s->beacon_aps[0].last_seen = 500;
    memcpy(s->beacon_aps[1].bssid, AP_B, 6);
    s->beacon_aps[1].channel = 1; s->beacon_aps[1].signal_dbm = -65;
    s->beacon_aps[1].last_seen = 505;
    s->beacon_count = 2;

    wifi_merge_reset(&s->wifi_merged);
    wifi_merge_from_beacons(s, 2);
    ASSERT_EQ(s->wifi_merged.count, 2);
    wifi_merged_t *a = wifi_merge_find(&s->wifi_merged, AP_A);
    ASSERT(a != NULL);
    ASSERT_EQ(a->sensor_mask, (1u<<2));
    ASSERT_EQ(a->channel, 6);
    ASSERT_EQ(a->best_rssi, -45);
    free(s);
}

void run_wifi_merge_tests(void) {
    TEST_SUITE("multi-radio wifi merge");
    RUN_TEST(test_single_radio_identity);
    RUN_TEST(test_two_radio_merge);
    RUN_TEST(test_duplicate_no_inflation);
    RUN_TEST(test_bad_sensor_id_dropped);
    RUN_TEST(test_zero_rssi_not_best);
    RUN_TEST(test_table_full_bounded);
    RUN_TEST(test_from_beacons_bridge);
}
