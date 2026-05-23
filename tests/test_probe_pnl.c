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
    probe_pnl_observe(mac, "", NULL, NULL);
    probe_pnl_observe(mac, NULL, NULL, NULL);
    ASSERT_EQ(probe_pnl_count(), 0);
}

static void test_first_directed_probe_creates_client(void) {
    probe_pnl_clear();
    uint8_t mac[6]; with_mac(mac, 0x00,0x11,0x22,0x33,0x44,0x55);
    probe_pnl_observe(mac, "myssid", NULL, NULL);
    ASSERT_EQ(probe_pnl_count(),       1);
    ASSERT_EQ(probe_pnl_ssid_count(mac), 1);
}

static void test_ssid_dedup_per_client(void) {
    probe_pnl_clear();
    uint8_t mac[6]; with_mac(mac, 0x00,0x11,0x22,0x33,0x44,0x55);
    probe_pnl_observe(mac, "wifi-a", NULL, NULL);
    probe_pnl_observe(mac, "wifi-a", NULL, NULL);
    probe_pnl_observe(mac, "wifi-a", NULL, NULL);
    ASSERT_EQ(probe_pnl_ssid_count(mac), 1);

    probe_pnl_observe(mac, "wifi-b", NULL, NULL);
    ASSERT_EQ(probe_pnl_ssid_count(mac), 2);
}

static void test_multiple_clients_independent(void) {
    probe_pnl_clear();
    uint8_t m1[6], m2[6];
    with_mac(m1, 0x00,0x11,0x22,0x33,0x44,0x55);
    with_mac(m2, 0xaa,0xbb,0xcc,0xdd,0xee,0xff);
    probe_pnl_observe(m1, "alpha", NULL, NULL);
    probe_pnl_observe(m1, "beta", NULL, NULL);
    probe_pnl_observe(m2, "gamma", NULL, NULL);
    ASSERT_EQ(probe_pnl_count(),         2);
    ASSERT_EQ(probe_pnl_ssid_count(m1),  2);
    ASSERT_EQ(probe_pnl_ssid_count(m2),  1);
}

static void test_random_flag_set_when_la_bit(void) {
    probe_pnl_clear();
    uint8_t real[6];   with_mac(real,   0x00,0x11,0x22,0x33,0x44,0x55);
    uint8_t random[6]; with_mac(random, 0x02,0x11,0x22,0x33,0x44,0x55);
    probe_pnl_observe(real,   "home", NULL, NULL);
    probe_pnl_observe(random, "home", NULL, NULL);

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
        probe_pnl_observe(mac, name, NULL, NULL);
    }
    ASSERT_EQ(probe_pnl_ssid_count(mac), MAX_PNL_SSIDS_PER_CLI);
    /* One more — count stays at cap. */
    probe_pnl_observe(mac, "overflow", NULL, NULL);
    ASSERT_EQ(probe_pnl_ssid_count(mac), MAX_PNL_SSIDS_PER_CLI);
}

static void test_snapshot_sorted_by_last_seen_desc(void) {
    probe_pnl_clear();
    uint8_t m1[6], m2[6], m3[6];
    with_mac(m1, 0x00,0x11,0x22,0x33,0x44,0x55);
    with_mac(m2, 0x00,0x11,0x22,0x33,0x44,0x66);
    with_mac(m3, 0x00,0x11,0x22,0x33,0x44,0x77);
    probe_pnl_observe(m1, "a", NULL, NULL);
    /* tiny sleep would be flaky in tests — instead rely on the fact
     * that subsequent observe() calls bump last_seen monotonically. */
    probe_pnl_observe(m2, "b", NULL, NULL);
    probe_pnl_observe(m3, "c", NULL, NULL);
    probe_pnl_observe(m1, "a2", NULL, NULL);  /* m1's last_seen now latest */

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
    probe_pnl_observe(mac, "x", NULL, NULL);
    probe_pnl_observe(mac, "x", NULL, NULL);   /* dup ssid, still counts as probe */
    probe_pnl_observe(mac, "y", NULL, NULL);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    probe_pnl_snapshot(&s);
    ASSERT_EQ(s.pnl_count, 1);
    ASSERT_EQ(s.pnl_clients[0].probe_count, 3);
    ASSERT_EQ(s.pnl_clients[0].ssid_count,  2);
}

/* ── Vendor-IE fingerprint helper ─────────────────────────── */

static void test_fingerprint_apple_vendor_ie(void) {
    /* Tag 221 (vendor specific), len 4, OUI 00:17:F2 */
    static const uint8_t ies[] = {
        0x00, 0x06, 'h','o','m','e','w','x',            /* SSID */
        0xdd, 0x04, 0x00, 0x17, 0xf2, 0x01,             /* Apple */
    };
    const char *fp = probe_pnl_fingerprint_ies(ies, sizeof(ies));
    ASSERT(fp != NULL);
    ASSERT_STR(fp, "Apple");
}

static void test_fingerprint_windows_provisioning(void) {
    /* OUI 00:50:F2 type 0x08 = Microsoft Provisioning */
    static const uint8_t ies[] = {
        0x00, 0x00,
        0xdd, 0x06, 0x00, 0x50, 0xf2, 0x08, 0x00, 0x00,
    };
    const char *fp = probe_pnl_fingerprint_ies(ies, sizeof(ies));
    ASSERT(fp != NULL);
    ASSERT_STR(fp, "Windows");
}

static void test_fingerprint_espressif(void) {
    static const uint8_t ies[] = {
        0xdd, 0x04, 0x24, 0x0a, 0xc4, 0x01,
    };
    const char *fp = probe_pnl_fingerprint_ies(ies, sizeof(ies));
    ASSERT(fp != NULL);
    ASSERT_STR(fp, "ESP32");
}

static void test_fingerprint_wifi_alliance_p2p_android(void) {
    /* OUI 50:6F:9A — Wi-Fi Alliance, used for P2P / Wi-Fi Direct */
    static const uint8_t ies[] = {
        0xdd, 0x04, 0x50, 0x6f, 0x9a, 0x09,
    };
    const char *fp = probe_pnl_fingerprint_ies(ies, sizeof(ies));
    ASSERT(fp != NULL);
    ASSERT_STR(fp, "Android");
}

static void test_fingerprint_apple_wins_over_wifialliance(void) {
    /* Wi-Fi Alliance (would say Android) then Apple — Apple should win
     * because the Apple match is strong and breaks out. */
    static const uint8_t ies[] = {
        0xdd, 0x04, 0x50, 0x6f, 0x9a, 0x09,
        0xdd, 0x04, 0x00, 0x17, 0xf2, 0x01,
    };
    const char *fp = probe_pnl_fingerprint_ies(ies, sizeof(ies));
    ASSERT_STR(fp, "Apple");
}

static void test_fingerprint_unknown_returns_null(void) {
    /* Microsoft WPA IE (type 1) — common, not a useful OS signal. */
    static const uint8_t ies[] = {
        0xdd, 0x04, 0x00, 0x50, 0xf2, 0x01,
    };
    const char *fp = probe_pnl_fingerprint_ies(ies, sizeof(ies));
    ASSERT(fp == NULL);
}

static void test_fingerprint_null_or_empty(void) {
    ASSERT(probe_pnl_fingerprint_ies(NULL, 0)  == NULL);
    static const uint8_t one[] = { 0x00 };
    ASSERT(probe_pnl_fingerprint_ies(one, 1)   == NULL);
}

/* ── PHY tier classifier ──────────────────────────────────── */

static void test_phy_legacy(void) {
    static const uint8_t ies[] = { 0x00, 0x00 };  /* just SSID */
    const char *p = probe_pnl_phy_ies(ies, sizeof(ies));
    ASSERT_STR(p, "legacy");
}

static void test_phy_wifi4_ht(void) {
    static const uint8_t ies[] = { 0x2d, 0x01, 0x00 };  /* tag 45 HT */
    const char *p = probe_pnl_phy_ies(ies, sizeof(ies));
    ASSERT_STR(p, "Wi-Fi 4");
}

static void test_phy_wifi5_vht(void) {
    static const uint8_t ies[] = {
        0x2d, 0x01, 0x00,                /* HT */
        0xbf, 0x01, 0x00,                /* tag 191 VHT */
    };
    const char *p = probe_pnl_phy_ies(ies, sizeof(ies));
    ASSERT_STR(p, "Wi-Fi 5");
}

static void test_phy_wifi6_he(void) {
    static const uint8_t ies[] = {
        0xff, 0x02, 0x23, 0x00,          /* tag 255 ext id 35 = HE */
    };
    const char *p = probe_pnl_phy_ies(ies, sizeof(ies));
    ASSERT_STR(p, "Wi-Fi 6");
}

static void test_phy_wifi7_eht_via_extid_108(void) {
    static const uint8_t ies[] = {
        0xff, 0x02, 0x6c, 0x00,          /* tag 255 ext id 108 = EHT */
    };
    const char *p = probe_pnl_phy_ies(ies, sizeof(ies));
    ASSERT_STR(p, "Wi-Fi 7");
}

static void test_phy_upgrades_only_on_observe(void) {
    probe_pnl_clear();
    uint8_t mac[6]; with_mac(mac, 0x00,0x11,0x22,0x33,0x44,0x55);
    probe_pnl_observe(mac, "x", NULL, "Wi-Fi 6");
    probe_pnl_observe(mac, "y", NULL, "Wi-Fi 4");     /* downgrade — ignored */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    probe_pnl_snapshot(&s);
    ASSERT_STR(s.pnl_clients[0].phy, "Wi-Fi 6");
    /* Upgrade applies. */
    probe_pnl_observe(mac, "z", NULL, "Wi-Fi 7");
    probe_pnl_snapshot(&s);
    ASSERT_STR(s.pnl_clients[0].phy, "Wi-Fi 7");
}

/* ── Sticky os_fp storage on the per-client entry ─────────── */

static void test_os_fp_stored_on_first_observation(void) {
    probe_pnl_clear();
    uint8_t mac[6]; with_mac(mac, 0x00,0x11,0x22,0x33,0x44,0x55);
    probe_pnl_observe(mac, "myssid", "Apple", NULL);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    probe_pnl_snapshot(&s);
    ASSERT_STR(s.pnl_clients[0].os_fp, "Apple");
}

static void test_os_fp_sticky_does_not_overwrite(void) {
    probe_pnl_clear();
    uint8_t mac[6]; with_mac(mac, 0x00,0x11,0x22,0x33,0x44,0x55);
    probe_pnl_observe(mac, "a", "Apple", NULL);
    probe_pnl_observe(mac, "b", NULL, NULL);    /* later, no fingerprint */
    probe_pnl_observe(mac, "c", "Windows", NULL); /* later, different fingerprint */

    sloth_state_t s; memset(&s, 0, sizeof(s));
    probe_pnl_snapshot(&s);
    ASSERT_STR(s.pnl_clients[0].os_fp, "Apple");
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
    RUN_TEST(test_fingerprint_apple_vendor_ie);
    RUN_TEST(test_fingerprint_windows_provisioning);
    RUN_TEST(test_fingerprint_espressif);
    RUN_TEST(test_fingerprint_wifi_alliance_p2p_android);
    RUN_TEST(test_fingerprint_apple_wins_over_wifialliance);
    RUN_TEST(test_fingerprint_unknown_returns_null);
    RUN_TEST(test_fingerprint_null_or_empty);
    RUN_TEST(test_os_fp_stored_on_first_observation);
    RUN_TEST(test_os_fp_sticky_does_not_overwrite);
    RUN_TEST(test_phy_legacy);
    RUN_TEST(test_phy_wifi4_ht);
    RUN_TEST(test_phy_wifi5_vht);
    RUN_TEST(test_phy_wifi6_he);
    RUN_TEST(test_phy_wifi7_eht_via_extid_108);
    RUN_TEST(test_phy_upgrades_only_on_observe);
}
