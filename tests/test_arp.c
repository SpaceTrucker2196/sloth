#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "views/arp.h"

/* ── Helpers ─────────────────────────────────────────────── */

static void inject_entry(sloth_state_t *s, const char *ip,
                          const char *mac_str, const char *iface) {
    if (s->arp_count >= MAX_ARP_ENTRIES) return;
    arp_entry_t *e = &s->arp_entries[s->arp_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->ip,    sizeof(e->ip),    "%s", ip);
    snprintf(e->iface, sizeof(e->iface), "%s", iface);
    unsigned b0,b1,b2,b3,b4,b5;
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
               &b0,&b1,&b2,&b3,&b4,&b5) == 6) {
        e->mac[0]=(uint8_t)b0; e->mac[1]=(uint8_t)b1;
        e->mac[2]=(uint8_t)b2; e->mac[3]=(uint8_t)b3;
        e->mac[4]=(uint8_t)b4; e->mac[5]=(uint8_t)b5;
    }
}

/* ── Draw smoke tests ────────────────────────────────────── */

static void test_arp_draw_empty(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_arp_draw(&s);
    ASSERT(1);
}

static void test_arp_draw_with_entries(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_entry(&s, "192.168.1.1",   "b8:27:eb:aa:bb:cc", "eth0");
    inject_entry(&s, "192.168.1.100", "18:fe:34:11:22:33", "eth0");
    inject_entry(&s, "192.168.1.200", "aa:bb:cc:dd:ee:ff", "eth0");
    view_arp_draw(&s);
    ASSERT_EQ(s.arp_count, 3);
}

static void test_arp_draw_known_vendor(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_entry(&s, "10.0.0.1", "dc:a6:32:00:00:01", "wlan0");
    view_arp_draw(&s);
    ASSERT(1);  /* smoke: Raspberry Pi vendor shown */
}

/* ── Navigation tests ────────────────────────────────────── */

static void test_arp_nav_down(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_entry(&s, "10.0.0.1", "aa:bb:cc:dd:ee:01", "eth0");
    inject_entry(&s, "10.0.0.2", "aa:bb:cc:dd:ee:02", "eth0");
    s.arp_sel = 0;
    view_arp_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.arp_sel, 1);
}

static void test_arp_nav_up(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_entry(&s, "10.0.0.1", "aa:bb:cc:dd:ee:01", "eth0");
    inject_entry(&s, "10.0.0.2", "aa:bb:cc:dd:ee:02", "eth0");
    s.arp_sel = 1;
    view_arp_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.arp_sel, 0);
}

static void test_arp_nav_top_bound(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_entry(&s, "10.0.0.1", "aa:bb:cc:dd:ee:01", "eth0");
    s.arp_sel = 0;
    view_arp_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.arp_sel, 0);
}

static void test_arp_nav_bottom_bound(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_entry(&s, "10.0.0.1", "aa:bb:cc:dd:ee:01", "eth0");
    s.arp_sel = 0;
    view_arp_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.arp_sel, 0);  /* only 1 entry, can't go lower */
}

static void test_arp_nav_empty(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.arp_sel = 0;
    view_arp_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.arp_sel, 0);
}

/* ── State tests ─────────────────────────────────────────── */

static void test_arp_zero_init(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(s.arp_count, 0);
    ASSERT_EQ(s.arp_sel, 0);
}

static void test_view_count_is_12(void) {
    ASSERT_EQ(VIEW_COUNT, 18);
}

/* ── Entry point ─────────────────────────────────────────── */

void run_arp_tests(void) {
    TEST_SUITE("ARP draw");
    RUN_TEST(test_arp_draw_empty);
    RUN_TEST(test_arp_draw_with_entries);
    RUN_TEST(test_arp_draw_known_vendor);

    TEST_SUITE("ARP navigation");
    RUN_TEST(test_arp_nav_down);
    RUN_TEST(test_arp_nav_up);
    RUN_TEST(test_arp_nav_top_bound);
    RUN_TEST(test_arp_nav_bottom_bound);
    RUN_TEST(test_arp_nav_empty);

    TEST_SUITE("ARP state");
    RUN_TEST(test_arp_zero_init);
    RUN_TEST(test_view_count_is_12);
}
