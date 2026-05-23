#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "assoc_track.h"
#include "beacon_snoop.h"

static void m(uint8_t out[6], uint8_t a, uint8_t b, uint8_t c,
                              uint8_t d, uint8_t e, uint8_t f) {
    out[0]=a; out[1]=b; out[2]=c; out[3]=d; out[4]=e; out[5]=f;
}

static void test_empty(void) {
    assoc_clear();
    ASSERT_EQ(assoc_count(), 0);
}

static void test_observe_creates_entry(void) {
    assoc_clear();
    uint8_t b[6], s[6];
    m(b, 0xaa,0xbb,0xcc,0xdd,0xee,0xff);
    m(s, 0x00,0x11,0x22,0x33,0x44,0x55);
    assoc_observe(b, s, "HomeWiFi", ASSOC_SRC_ASSOC, -50, 6);
    ASSERT_EQ(assoc_count(), 1);

    sloth_state_t st; memset(&st, 0, sizeof(st));
    assoc_snapshot(&st);
    ASSERT_EQ(st.assoc_count, 1);
    ASSERT_EQ(memcmp(st.assocs[0].bssid,   b, 6), 0);
    ASSERT_EQ(memcmp(st.assocs[0].sta_mac, s, 6), 0);
    ASSERT_STR(st.assocs[0].ssid, "HomeWiFi");
    ASSERT_EQ(st.assocs[0].source, ASSOC_SRC_ASSOC);
}

static void test_eapol_promotes_source_over_assoc(void) {
    assoc_clear();
    uint8_t b[6], s[6];
    m(b, 0xaa,0xbb,0xcc,0xdd,0xee,0xff);
    m(s, 0x00,0x11,0x22,0x33,0x44,0x55);
    assoc_observe(b, s, NULL, ASSOC_SRC_ASSOC, -50, 6);
    assoc_observe(b, s, NULL, ASSOC_SRC_EAPOL, -50, 6);  /* stronger */
    sloth_state_t st; memset(&st, 0, sizeof(st));
    assoc_snapshot(&st);
    ASSERT_EQ(st.assocs[0].source, ASSOC_SRC_EAPOL);

    /* Weaker source after EAPOL must not downgrade. */
    assoc_observe(b, s, NULL, ASSOC_SRC_ASSOC, -50, 6);
    assoc_snapshot(&st);
    ASSERT_EQ(st.assocs[0].source, ASSOC_SRC_EAPOL);
}

static void test_forget_removes_entry(void) {
    assoc_clear();
    uint8_t b[6], s[6];
    m(b, 0xaa,0xbb,0xcc,0xdd,0xee,0xff);
    m(s, 0x00,0x11,0x22,0x33,0x44,0x55);
    assoc_observe(b, s, NULL, ASSOC_SRC_EAPOL, -50, 6);
    ASSERT_EQ(assoc_count(), 1);
    assoc_forget(b, s);
    ASSERT_EQ(assoc_count(), 0);
}

static void test_multicast_bssid_rejected(void) {
    assoc_clear();
    uint8_t b_mcast[6], s[6];
    m(b_mcast, 0x01, 0x00, 0x5e, 0x00, 0x00, 0x01);   /* multicast bit */
    m(s,       0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    assoc_observe(b_mcast, s, NULL, ASSOC_SRC_ASSOC, -50, 6);
    ASSERT_EQ(assoc_count(), 0);
}

static void test_multiple_stas_per_bssid(void) {
    assoc_clear();
    uint8_t b[6]; m(b, 0xaa,0xbb,0xcc,0xdd,0xee,0xff);
    uint8_t s1[6]; m(s1, 0x00,0x11,0x22,0x33,0x44,0x55);
    uint8_t s2[6]; m(s2, 0x00,0x11,0x22,0x33,0x44,0x66);
    assoc_observe(b, s1, NULL, ASSOC_SRC_EAPOL, -50, 6);
    assoc_observe(b, s2, NULL, ASSOC_SRC_EAPOL, -55, 6);
    ASSERT_EQ(assoc_count(), 2);
}

static void test_sta_random_flag_set(void) {
    assoc_clear();
    uint8_t b[6]; m(b, 0xaa,0xbb,0xcc,0xdd,0xee,0xff);
    uint8_t rand[6]; m(rand, 0x02,0x11,0x22,0x33,0x44,0x55);
    assoc_observe(b, rand, NULL, ASSOC_SRC_ASSOC, -50, 6);
    sloth_state_t st; memset(&st, 0, sizeof(st));
    assoc_snapshot(&st);
    ASSERT_EQ(st.assocs[0].sta_random, 1);
}

static void test_ssid_backfilled_from_beacon_table(void) {
    /* No SSID in observe() → snapshot should pull it from beacon_snoop. */
    assoc_clear();
    beacon_clear();
    uint8_t b[6]; m(b, 0xaa,0xbb,0xcc,0xdd,0xee,0xff);
    uint8_t s[6]; m(s, 0x00,0x11,0x22,0x33,0x44,0x55);
    assoc_observe(b, s, NULL, ASSOC_SRC_EAPOL, -50, 6);
    /* After-the-fact beacon observation. */
    beacon_record(b, "Lab-WiFi", -50, 6, "WPA2", 102, NULL);
    sloth_state_t st; memset(&st, 0, sizeof(st));
    assoc_snapshot(&st);
    ASSERT_STR(st.assocs[0].ssid, "Lab-WiFi");
}

void run_assoc_track_tests(void) {
    TEST_SUITE("assoc_track");
    RUN_TEST(test_empty);
    RUN_TEST(test_observe_creates_entry);
    RUN_TEST(test_eapol_promotes_source_over_assoc);
    RUN_TEST(test_forget_removes_entry);
    RUN_TEST(test_multicast_bssid_rejected);
    RUN_TEST(test_multiple_stas_per_bssid);
    RUN_TEST(test_sta_random_flag_set);
    RUN_TEST(test_ssid_backfilled_from_beacon_table);
}
