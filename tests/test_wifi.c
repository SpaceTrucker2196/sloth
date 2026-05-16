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
}
