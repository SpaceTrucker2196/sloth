#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "tui.h"
#include "sloth.h"
#include "views/wifi.h"

static void make_wifi_state(sloth_state_t *s, int n) {
    memset(s, 0, sizeof(*s));
    for (int i = 0; i < n && i < MAX_WIFI_APS; i++) {
        snprintf(s->aps[i].ssid,  sizeof(s->aps[i].ssid),  "AP%d", i);
        snprintf(s->aps[i].bssid, sizeof(s->aps[i].bssid), "aa:bb:cc:dd:ee:%02x", i);
        s->aps[i].signal_dbm = -30 - i * 3;
        s->aps[i].channel    = (i % 11) + 1;
        s->aps[i].status     = -1;
        memcpy(s->aps[i].enc, "WPA2", 5);
    }
    s->ap_count = n;
    s->wifi_sel = 0;
}

/* ── Navigation tests ────────────────────────────────────── */

void test_wifi_nav_down(void) {
    sloth_state_t s;
    make_wifi_state(&s, 5);

    view_wifi_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.wifi_sel, 1);
    view_wifi_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.wifi_sel, 2);
}

void test_wifi_nav_up(void) {
    sloth_state_t s;
    make_wifi_state(&s, 5);
    s.wifi_sel = 3;

    view_wifi_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.wifi_sel, 2);
    view_wifi_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.wifi_sel, 1);
}

void test_wifi_nav_top_bound(void) {
    sloth_state_t s;
    make_wifi_state(&s, 3);
    s.wifi_sel = 0;

    view_wifi_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.wifi_sel, 0);  /* stays at top */
}

void test_wifi_nav_bottom_bound(void) {
    sloth_state_t s;
    make_wifi_state(&s, 3);
    s.wifi_sel = 2;  /* last */

    view_wifi_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.wifi_sel, 2);  /* stays at bottom */
}

void test_wifi_nav_empty(void) {
    sloth_state_t s;
    make_wifi_state(&s, 0);

    view_wifi_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.wifi_sel, 0);
    view_wifi_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.wifi_sel, 0);
}

void test_wifi_nav_single(void) {
    sloth_state_t s;
    make_wifi_state(&s, 1);
    s.wifi_sel = 0;

    view_wifi_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.wifi_sel, 0);  /* no movement with one entry */
    view_wifi_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.wifi_sel, 0);
}

/* ── Render smoke test (no crash with APs) ───────────────── */

void test_wifi_draw_no_crash(void) {
    sloth_state_t s;
    make_wifi_state(&s, 5);
    s.wifi_sel = 2;
    view_wifi_draw(&s);
    ASSERT_LINE_HAS(0, "WiFi: 5 APs");
    for (int i = 0; i < 5; i++) {
        char ssid[8];
        snprintf(ssid, sizeof(ssid), "AP%d ", i);
        int y = runner_screen_find(ssid);
        ASSERT(y >= 0);
        ASSERT_EQ(tui_test_is_reverse(y, 1), i == 2 ? 1 : 0);
    }
    /* AP0 at -30 dBm is a full bar; AP4 at -42 two cells short. */
    ASSERT_LINE_HAS(runner_screen_find("AP0 "),
        "[\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88"
        "\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88] -30");
    ASSERT_LINE_HAS(runner_screen_find("AP4 "), "\xe2\x96\x91\xe2\x96\x91] -42");
}

void test_wifi_draw_empty_no_crash(void) {
    sloth_state_t s;
    make_wifi_state(&s, 0);
    view_wifi_draw(&s);
    ASSERT_LINE_HAS(0, "WiFi: 0 APs");
    ASSERT_SCREEN_HAS("(scanning...");
}

/* ── Detail panel tests ──────────────────────────────────── */

void test_wifi_enter_opens_detail(void) {
    sloth_state_t s;
    make_wifi_state(&s, 3);
    s.wifi_sel    = 1;
    s.wifi_detail = 0;

    view_wifi_key(&s, '\r');
    ASSERT_EQ(s.wifi_detail, 1);
}

void test_wifi_esc_closes_detail(void) {
    sloth_state_t s;
    make_wifi_state(&s, 3);
    s.wifi_sel    = 1;
    s.wifi_detail = 1;

    view_wifi_key(&s, '\033');
    ASSERT_EQ(s.wifi_detail, 0);
}

void test_wifi_nav_blocked_in_detail(void) {
    sloth_state_t s;
    make_wifi_state(&s, 3);
    s.wifi_sel    = 0;
    s.wifi_detail = 1;

    /* navigation keys must not change wifi_sel while detail is open */
    view_wifi_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.wifi_sel, 0);
}

void test_wifi_enter_noop_when_empty(void) {
    sloth_state_t s;
    make_wifi_state(&s, 0);
    s.wifi_detail = 0;

    view_wifi_key(&s, '\r');
    ASSERT_EQ(s.wifi_detail, 0);  /* no APs → detail stays closed */
}

void test_wifi_detail_draw_no_sta(void) {
    sloth_state_t s;
    make_wifi_state(&s, 2);
    s.wifi_sel      = 0;
    s.wifi_detail   = 1;
    s.wifi_sta_count = 0;
    view_wifi_draw(&s);
    ASSERT_LINE_HAS(0, "AP0  [Esc] back");
    ASSERT_SCREEN_HAS("BSSID: aa:bb:cc:dd:ee:00");
    ASSERT_SCREEN_HAS("(not associated");
    ASSERT_SCREEN_LACKS("TX rate:");
}

void test_wifi_detail_draw_with_sta(void) {
    sloth_state_t s;
    make_wifi_state(&s, 2);
    s.wifi_sel    = 0;
    s.wifi_detail = 1;

    /* plant a station matching the selected AP's bssid */
    memcpy(s.wifi_stas[0].mac, s.aps[0].bssid, 18);
    s.wifi_stas[0].signal_dbm    = -55;
    s.wifi_stas[0].tx_rate_kbps  = 54000;
    s.wifi_stas[0].rx_rate_kbps  = 54000;
    s.wifi_stas[0].connected_secs = 3600;
    s.wifi_stas[0].inactive_ms   = 10;
    s.wifi_stas[0].tx_bytes      = 1000000;
    s.wifi_stas[0].rx_bytes      = 500000;
    s.wifi_sta_count             = 1;

    view_wifi_draw(&s);
    ASSERT_SCREEN_HAS("TX rate: 54.0 Mbps");
    ASSERT_SCREEN_HAS("RX rate: 54.0 Mbps");
    /* The unit follows the value; it used to be padded out to the
     * second column ("-55                 dBm"). */
    ASSERT_SCREEN_HAS("Signal:  -55 dBm");
    ASSERT_SCREEN_HAS("Connected: 1h 00m");
    ASSERT_SCREEN_HAS("Inactive: 10 ms");
    ASSERT_SCREEN_LACKS("(not associated");
}

void test_wifi_associated_status(void) {
    sloth_state_t s;
    make_wifi_state(&s, 3);
    s.aps[1].status = WIFI_STATUS_ASSOC;

    view_wifi_draw(&s);
    /* The associated AP alone carries the '*' marker in column 0. */
    ASSERT_EQ(runner_find_col(runner_screen_find("AP1 "), "*AP1"), 0);
    ASSERT_EQ(runner_find_col(runner_screen_find("AP0 "), " AP0"), 0);
    ASSERT_EQ(runner_find_col(runner_screen_find("AP2 "), " AP2"), 0);

    /* the associated AP's status should be visible */
    ASSERT_EQ(s.aps[1].status, WIFI_STATUS_ASSOC);
    ASSERT_EQ(s.aps[0].status, -1);
}

void run_wifi_tests(void) {
    TEST_SUITE("view_wifi_key");
    RUN_TEST(test_wifi_nav_down);
    RUN_TEST(test_wifi_nav_up);
    RUN_TEST(test_wifi_nav_top_bound);
    RUN_TEST(test_wifi_nav_bottom_bound);
    RUN_TEST(test_wifi_nav_empty);
    RUN_TEST(test_wifi_nav_single);

    TEST_SUITE("view_wifi_draw");
    RUN_TEST(test_wifi_draw_no_crash);
    RUN_TEST(test_wifi_draw_empty_no_crash);

    TEST_SUITE("wifi detail panel");
    RUN_TEST(test_wifi_enter_opens_detail);
    RUN_TEST(test_wifi_esc_closes_detail);
    RUN_TEST(test_wifi_nav_blocked_in_detail);
    RUN_TEST(test_wifi_enter_noop_when_empty);
    RUN_TEST(test_wifi_detail_draw_no_sta);
    RUN_TEST(test_wifi_detail_draw_with_sta);
    RUN_TEST(test_wifi_associated_status);
}
