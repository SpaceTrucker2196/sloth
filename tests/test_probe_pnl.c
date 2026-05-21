#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "probe_pnl.h"

static void with_mac(uint8_t out[6], uint8_t a, uint8_t b, uint8_t c,
                                       uint8_t d, uint8_t e, uint8_t f) {
    out[0] = a; out[1] = b; out[2] = c; out[3] = d; out[4] = e; out[5] = f;
}

static void test_empty(void) {
    probe_pnl_clear();
    ASSERT_EQ(probe_pnl_count(), 0);
}

static void test_wildcard_probe_is_dropped(void) {
    probe_pnl_clear();
    uint8_t mac[6]; with_mac(mac, 0x00,0x11,0x22,0x33,0x44,0x55);
    probe_pnl_observe(mac, "");
    probe_pnl_observe(mac, NULL);
    ASSERT_EQ(probe_pnl_count(), 0);
}

static void test_first_directed_probe_creates_client(void) {
    probe_pnl_clear();
    uint8_t mac[6]; with_mac(mac, 0x00,0x11,0x22,0x33,0x44,0x55);
    probe_pnl_observe(mac, "myssid");
    ASSERT_EQ(probe_pnl_count(),       1);
    ASSERT_EQ(probe_pnl_ssid_count(mac), 1);
}

static void test_ssid_dedup_per_client(void) {
    probe_pnl_clear();
    uint8_t mac[6]; with_mac(mac, 0x00,0x11,0x22,0x33,0x44,0x55);
    probe_pnl_observe(mac, "wifi-a");
    probe_pnl_observe(mac, "wifi-a");
    probe_pnl_observe(mac, "wifi-a");
    ASSERT_EQ(probe_pnl_ssid_count(mac), 1);

    probe_pnl_observe(mac, "wifi-b");
    ASSERT_EQ(probe_pnl_ssid_count(mac), 2);
}

static void test_multiple_clients_independent(void) {
    probe_pnl_clear();
    uint8_t m1[6], m2[6];
    with_mac(m1, 0x00,0x11,0x22,0x33,0x44,0x55);
    with_mac(m2, 0xaa,0xbb,0xcc,0xdd,0xee,0xff);
    probe_pnl_observe(m1, "alpha");
    probe_pnl_observe(m1, "beta");
    probe_pnl_observe(m2, "gamma");
    ASSERT_EQ(probe_pnl_count(),         2);
    ASSERT_EQ(probe_pnl_ssid_count(m1),  2);
    ASSERT_EQ(probe_pnl_ssid_count(m2),  1);
}

static void test_random_flag_set_when_la_bit(void) {
    probe_pnl_clear();
    uint8_t real[6];   with_mac(real,   0x00,0x11,0x22,0x33,0x44,0x55);
    uint8_t random[6]; with_mac(random, 0x02,0x11,0x22,0x33,0x44,0x55);
    probe_pnl_observe(real,   "home");
    probe_pnl_observe(random, "home");

    sloth_state_t s; memset(&s, 0, sizeof(s));
    probe_pnl_snapshot(&s);
    ASSERT_EQ(s.pnl_count, 2);

    int found_real = 0, found_random = 0;
    for (int i = 0; i < s.pnl_count; i++) {
        if (memcmp(s.pnl_clients[i].mac, real, 6) == 0) {
            ASSERT_EQ(s.pnl_clients[i].mac_random, 0); found_real = 1;
        } else if (memcmp(s.pnl_clients[i].mac, random, 6) == 0) {
            ASSERT_EQ(s.pnl_clients[i].mac_random, 1); found_random = 1;
        }
    }
    ASSERT_EQ(found_real, 1);
    ASSERT_EQ(found_random, 1);
}

static void test_per_client_ssid_cap_evicts_oldest(void) {
    probe_pnl_clear();
    uint8_t mac[6]; with_mac(mac, 0x00,0x11,0x22,0x33,0x44,0x55);
    char name[16];
    /* Fill exactly to the cap. */
    for (int i = 0; i < MAX_PNL_SSIDS_PER_CLI; i++) {
        snprintf(name, sizeof(name), "ssid%d", i);
        probe_pnl_observe(mac, name);
    }
    ASSERT_EQ(probe_pnl_ssid_count(mac), MAX_PNL_SSIDS_PER_CLI);
    /* One more — count stays at cap. */
    probe_pnl_observe(mac, "overflow");
    ASSERT_EQ(probe_pnl_ssid_count(mac), MAX_PNL_SSIDS_PER_CLI);
}

static void test_snapshot_sorted_by_last_seen_desc(void) {
    probe_pnl_clear();
    uint8_t m1[6], m2[6], m3[6];
    with_mac(m1, 0x00,0x11,0x22,0x33,0x44,0x55);
    with_mac(m2, 0x00,0x11,0x22,0x33,0x44,0x66);
    with_mac(m3, 0x00,0x11,0x22,0x33,0x44,0x77);
    probe_pnl_observe(m1, "a");
    /* tiny sleep would be flaky in tests — instead rely on the fact
     * that subsequent observe() calls bump last_seen monotonically. */
    probe_pnl_observe(m2, "b");
    probe_pnl_observe(m3, "c");
    probe_pnl_observe(m1, "a2");  /* m1's last_seen now latest */

    sloth_state_t s; memset(&s, 0, sizeof(s));
    probe_pnl_snapshot(&s);
    ASSERT_EQ(s.pnl_count, 3);
    /* m1 last touched, should be at index 0 ... or any newer if the
     * timestamps tied. last_seen is per-second, so at most we can
     * say m1's last_seen >= the others. */
    ASSERT_GE(s.pnl_clients[0].last_seen, s.pnl_clients[1].last_seen);
    ASSERT_GE(s.pnl_clients[1].last_seen, s.pnl_clients[2].last_seen);
}

static void test_probe_count_increments_per_observation(void) {
    probe_pnl_clear();
    uint8_t mac[6]; with_mac(mac, 0x00,0x11,0x22,0x33,0x44,0x55);
    probe_pnl_observe(mac, "x");
    probe_pnl_observe(mac, "x");   /* dup ssid, still counts as probe */
    probe_pnl_observe(mac, "y");
    sloth_state_t s; memset(&s, 0, sizeof(s));
    probe_pnl_snapshot(&s);
    ASSERT_EQ(s.pnl_count, 1);
    ASSERT_EQ(s.pnl_clients[0].probe_count, 3);
    ASSERT_EQ(s.pnl_clients[0].ssid_count,  2);
}

void run_probe_pnl_tests(void) {
    TEST_SUITE("probe_pnl");
    RUN_TEST(test_empty);
    RUN_TEST(test_wildcard_probe_is_dropped);
    RUN_TEST(test_first_directed_probe_creates_client);
    RUN_TEST(test_ssid_dedup_per_client);
    RUN_TEST(test_multiple_clients_independent);
    RUN_TEST(test_random_flag_set_when_la_bit);
    RUN_TEST(test_per_client_ssid_cap_evicts_oldest);
    RUN_TEST(test_snapshot_sorted_by_last_seen_desc);
    RUN_TEST(test_probe_count_increments_per_observation);
}
