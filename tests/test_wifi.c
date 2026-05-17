#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "ntop.h"
#include "views/wifi.h"

static void make_wifi_state(ntop_state_t *s, int n) {
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
    ntop_state_t s;
    make_wifi_state(&s, 5);

    view_wifi_key(&s, NTOP_KEY_DOWN);
    ASSERT_EQ(s.wifi_sel, 1);
    view_wifi_key(&s, NTOP_KEY_DOWN);
    ASSERT_EQ(s.wifi_sel, 2);
}

void test_wifi_nav_up(void) {
    ntop_state_t s;
    make_wifi_state(&s, 5);
    s.wifi_sel = 3;

    view_wifi_key(&s, NTOP_KEY_UP);
    ASSERT_EQ(s.wifi_sel, 2);
    view_wifi_key(&s, NTOP_KEY_UP);
    ASSERT_EQ(s.wifi_sel, 1);
}

void test_wifi_nav_top_bound(void) {
    ntop_state_t s;
    make_wifi_state(&s, 3);
    s.wifi_sel = 0;

    view_wifi_key(&s, NTOP_KEY_UP);
    ASSERT_EQ(s.wifi_sel, 0);  /* stays at top */
}

void test_wifi_nav_bottom_bound(void) {
    ntop_state_t s;
    make_wifi_state(&s, 3);
    s.wifi_sel = 2;  /* last */

    view_wifi_key(&s, NTOP_KEY_DOWN);
    ASSERT_EQ(s.wifi_sel, 2);  /* stays at bottom */
}

void test_wifi_nav_empty(void) {
    ntop_state_t s;
    make_wifi_state(&s, 0);

    view_wifi_key(&s, NTOP_KEY_DOWN);
    ASSERT_EQ(s.wifi_sel, 0);
    view_wifi_key(&s, NTOP_KEY_UP);
    ASSERT_EQ(s.wifi_sel, 0);
}

void test_wifi_nav_single(void) {
    ntop_state_t s;
    make_wifi_state(&s, 1);
    s.wifi_sel = 0;

    view_wifi_key(&s, NTOP_KEY_DOWN);
    ASSERT_EQ(s.wifi_sel, 0);  /* no movement with one entry */
    view_wifi_key(&s, NTOP_KEY_UP);
    ASSERT_EQ(s.wifi_sel, 0);
}

/* ── Render smoke test (no crash with APs) ───────────────── */

void test_wifi_draw_no_crash(void) {
    ntop_state_t s;
    make_wifi_state(&s, 5);
    s.wifi_sel = 2;
    view_wifi_draw(&s);   /* just must not crash */
    ASSERT(1);
}

void test_wifi_draw_empty_no_crash(void) {
    ntop_state_t s;
    make_wifi_state(&s, 0);
    view_wifi_draw(&s);
    ASSERT(1);
}

/* ── Detail panel tests ──────────────────────────────────── */

void test_wifi_enter_opens_detail(void) {
    ntop_state_t s;
    make_wifi_state(&s, 3);
    s.wifi_sel    = 1;
    s.wifi_detail = 0;

    view_wifi_key(&s, '\r');
    ASSERT_EQ(s.wifi_detail, 1);
}

void test_wifi_esc_closes_detail(void) {
    ntop_state_t s;
    make_wifi_state(&s, 3);
    s.wifi_sel    = 1;
    s.wifi_detail = 1;

    view_wifi_key(&s, '\033');
    ASSERT_EQ(s.wifi_detail, 0);
}

void test_wifi_nav_blocked_in_detail(void) {
    ntop_state_t s;
    make_wifi_state(&s, 3);
    s.wifi_sel    = 0;
    s.wifi_detail = 1;

    /* navigation keys must not change wifi_sel while detail is open */
    view_wifi_key(&s, NTOP_KEY_DOWN);
    ASSERT_EQ(s.wifi_sel, 0);
}

void test_wifi_enter_noop_when_empty(void) {
    ntop_state_t s;
    make_wifi_state(&s, 0);
    s.wifi_detail = 0;

    view_wifi_key(&s, '\r');
    ASSERT_EQ(s.wifi_detail, 0);  /* no APs → detail stays closed */
}

void test_wifi_detail_draw_no_sta(void) {
    ntop_state_t s;
    make_wifi_state(&s, 2);
    s.wifi_sel      = 0;
    s.wifi_detail   = 1;
    s.wifi_sta_count = 0;
    view_wifi_draw(&s);  /* must not crash with no station data */
    ASSERT(1);
}

void test_wifi_detail_draw_with_sta(void) {
    ntop_state_t s;
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

    view_wifi_draw(&s);  /* must not crash with station data */
    ASSERT(1);
}

void test_wifi_associated_status(void) {
    ntop_state_t s;
    make_wifi_state(&s, 3);
    s.aps[1].status = WIFI_STATUS_ASSOC;

    /* draw must not crash with one associated AP */
    view_wifi_draw(&s);
    ASSERT(1);

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
