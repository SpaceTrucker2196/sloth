#include <string.h>
#include <time.h>
#include "runner.h"
#include "ntop.h"
#include "views/probe.h"
#include "capture/probe.h"

/* ── Helpers ─────────────────────────────────────────────── */

static void inject_client(ntop_state_t *s, const char *mac_str,
                          const char *ssid, int8_t sig, int ch) {
    if (s->probe_count >= MAX_PROBE_CLIENTS) return;
    probe_client_t *c = &s->probe_clients[s->probe_count++];
    memset(c, 0, sizeof(*c));
    /* parse colon-separated hex MAC */
    unsigned b0,b1,b2,b3,b4,b5;
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &b0,&b1,&b2,&b3,&b4,&b5) == 6) {
        c->mac[0]=(uint8_t)b0; c->mac[1]=(uint8_t)b1; c->mac[2]=(uint8_t)b2;
        c->mac[3]=(uint8_t)b3; c->mac[4]=(uint8_t)b4; c->mac[5]=(uint8_t)b5;
    }
    strncpy(c->ssid, ssid, sizeof(c->ssid) - 1);
    c->signal_dbm  = sig;
    c->channel     = ch;
    c->last_seen   = time(NULL);
    c->frame_count = 1;
}

/* ── Draw smoke tests ────────────────────────────────────── */

static void test_probe_draw_empty_no_crash(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    view_probe_draw(&s);
    ASSERT(1);
}

static void test_probe_draw_no_iface_message(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    s.probe_iface[0] = '\0';
    view_probe_draw(&s);
    ASSERT(1);  /* smoke: no crash */
}

static void test_probe_draw_with_clients(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_client(&s, "aa:bb:cc:dd:ee:01", "homenet", -67, 6);
    inject_client(&s, "11:22:33:44:55:66", "",        -82, 1);
    inject_client(&s, "de:ad:be:ef:00:01", "office",  -55, 11);
    view_probe_draw(&s);
    ASSERT_EQ(s.probe_count, 3);
}

static void test_probe_draw_wildcard_ssid(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_client(&s, "aa:bb:cc:dd:ee:ff", "", -70, 6);
    view_probe_draw(&s);
    ASSERT(1);
}

/* ── Key handler tests ───────────────────────────────────── */

static void test_probe_nav_down(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    inject_client(&s, "aa:bb:cc:dd:ee:01", "a", -60, 6);
    inject_client(&s, "aa:bb:cc:dd:ee:02", "b", -65, 6);
    s.probe_sel = 0;
    view_probe_key(&s, NTOP_KEY_DOWN);
    ASSERT_EQ(s.probe_sel, 1);
}

static void test_probe_nav_up(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    inject_client(&s, "aa:bb:cc:dd:ee:01", "a", -60, 6);
    inject_client(&s, "aa:bb:cc:dd:ee:02", "b", -65, 6);
    s.probe_sel = 1;
    view_probe_key(&s, NTOP_KEY_UP);
    ASSERT_EQ(s.probe_sel, 0);
}

static void test_probe_nav_top_bound(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    inject_client(&s, "aa:bb:cc:dd:ee:01", "a", -60, 6);
    s.probe_sel = 0;
    view_probe_key(&s, NTOP_KEY_UP);
    ASSERT_EQ(s.probe_sel, 0);
}

static void test_probe_nav_bottom_bound(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    inject_client(&s, "aa:bb:cc:dd:ee:01", "a", -60, 6);
    s.probe_sel = 0;
    view_probe_key(&s, NTOP_KEY_DOWN);
    ASSERT_EQ(s.probe_sel, 0);
}

static void test_probe_nav_empty(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    s.probe_sel = 0;
    view_probe_key(&s, NTOP_KEY_DOWN);
    ASSERT_EQ(s.probe_sel, 0);
}

static void test_probe_clear_key(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    inject_client(&s, "aa:bb:cc:dd:ee:01", "a", -60, 6);
    inject_client(&s, "aa:bb:cc:dd:ee:02", "b", -65, 6);
    s.probe_sel = 1;
    view_probe_key(&s, 'c');
    ASSERT_EQ(s.probe_count, 0);
    ASSERT_EQ(s.probe_sel,   0);
}

static void test_probe_clear_key_upper(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    inject_client(&s, "aa:bb:cc:dd:ee:01", "a", -60, 6);
    view_probe_key(&s, 'C');
    ASSERT_EQ(s.probe_count, 0);
}

/* ── Entry point ─────────────────────────────────────────── */

void run_probe_tests(void) {
    TEST_SUITE("probe draw");
    RUN_TEST(test_probe_draw_empty_no_crash);
    RUN_TEST(test_probe_draw_no_iface_message);
    RUN_TEST(test_probe_draw_with_clients);
    RUN_TEST(test_probe_draw_wildcard_ssid);

    TEST_SUITE("probe key handler");
    RUN_TEST(test_probe_nav_down);
    RUN_TEST(test_probe_nav_up);
    RUN_TEST(test_probe_nav_top_bound);
    RUN_TEST(test_probe_nav_bottom_bound);
    RUN_TEST(test_probe_nav_empty);
    RUN_TEST(test_probe_clear_key);
    RUN_TEST(test_probe_clear_key_upper);
}
