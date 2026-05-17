#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "views/arp.h"

/* ── Helpers ─────────────────────────────────────────────── */

static void inject_arp(sloth_state_t *s, const char *ip,
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

static void inject_lease(sloth_state_t *s, const char *ip,
                         const char *hostname, time_t expire) {
    if (s->dhcp_count >= MAX_DHCP_LEASES) return;
    dhcp_lease_t *l = &s->dhcp_leases[s->dhcp_count++];
    memset(l, 0, sizeof(*l));
    snprintf(l->ip,       sizeof(l->ip),       "%s", ip);
    snprintf(l->hostname, sizeof(l->hostname),  "%s", hostname);
    l->expire = expire;
}

/* ── State tests ─────────────────────────────────────────── */

static void test_dhcp_zero_init(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(s.dhcp_count, 0);
}

static void test_dhcp_max_leases_defined(void) {
    ASSERT(MAX_DHCP_LEASES >= 16);
}

/* ── Draw smoke tests ────────────────────────────────────── */

static void test_draw_no_arp_no_leases(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_arp_draw(&s);
    ASSERT(1);
}

static void test_draw_arp_with_lease(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_arp(&s,   "192.168.1.1", "b8:27:eb:aa:bb:cc", "eth0");
    inject_lease(&s, "192.168.1.1", "router",  time(NULL) + 3600);
    view_arp_draw(&s);
    ASSERT_EQ(s.arp_count,  1);
    ASSERT_EQ(s.dhcp_count, 1);
}

static void test_draw_arp_no_lease_for_ip(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_arp(&s,   "10.0.0.1",   "aa:bb:cc:dd:ee:01", "eth0");
    inject_lease(&s, "10.0.0.99",  "other",   time(NULL) + 7200);
    view_arp_draw(&s);
    ASSERT_EQ(s.arp_count,  1);
    ASSERT_EQ(s.dhcp_count, 1);
}

static void test_draw_multiple_leases(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_arp(&s,   "192.168.1.1",   "b8:27:eb:aa:bb:cc", "eth0");
    inject_arp(&s,   "192.168.1.100", "18:fe:34:11:22:33", "eth0");
    inject_arp(&s,   "192.168.1.200", "aa:bb:cc:dd:ee:ff", "eth0");
    inject_lease(&s, "192.168.1.1",   "router",   time(NULL) + 3600);
    inject_lease(&s, "192.168.1.100", "laptop",   time(NULL) + 7200);
    view_arp_draw(&s);
    ASSERT_EQ(s.arp_count,  3);
    ASSERT_EQ(s.dhcp_count, 2);
}

static void test_draw_expired_lease(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_arp(&s,   "10.0.0.5", "aa:bb:cc:dd:ee:05", "eth0");
    inject_lease(&s, "10.0.0.5", "oldhost", (time_t)1);  /* very old */
    view_arp_draw(&s);
    ASSERT(1);
}

static void test_draw_unknown_expire(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_arp(&s,   "10.0.0.6", "aa:bb:cc:dd:ee:06", "eth0");
    inject_lease(&s, "10.0.0.6", "nas", 0);  /* expire=0 → unknown */
    view_arp_draw(&s);
    ASSERT(1);
}

static void test_draw_empty_hostname_ignored(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_arp(&s,   "10.0.0.7", "aa:bb:cc:dd:ee:07", "eth0");
    /* hostname="" → dhcp_lookup returns NULL */
    inject_lease(&s, "10.0.0.7", "", time(NULL) + 3600);
    view_arp_draw(&s);
    ASSERT(1);
}

/* ── Lease struct capacity ───────────────────────────────── */

static void test_lease_ip_field_size(void) {
    dhcp_lease_t l;
    memset(&l, 0, sizeof(l));
    ASSERT(sizeof(l.ip) >= 16);  /* at least IPv4 dotted + null */
}

static void test_lease_hostname_field_size(void) {
    dhcp_lease_t l;
    memset(&l, 0, sizeof(l));
    ASSERT(sizeof(l.hostname) >= 32);
}

/* ── Entry point ─────────────────────────────────────────── */

void run_dhcp_tests(void) {
    TEST_SUITE("dhcp/state");
    RUN_TEST(test_dhcp_zero_init);
    RUN_TEST(test_dhcp_max_leases_defined);
    RUN_TEST(test_lease_ip_field_size);
    RUN_TEST(test_lease_hostname_field_size);

    TEST_SUITE("dhcp/draw");
    RUN_TEST(test_draw_no_arp_no_leases);
    RUN_TEST(test_draw_arp_with_lease);
    RUN_TEST(test_draw_arp_no_lease_for_ip);
    RUN_TEST(test_draw_multiple_leases);
    RUN_TEST(test_draw_expired_lease);
    RUN_TEST(test_draw_unknown_expire);
    RUN_TEST(test_draw_empty_hostname_ignored);
}
