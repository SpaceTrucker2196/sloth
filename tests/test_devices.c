#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "devices.h"
#include "views/devices.h"

static void add_arp(sloth_state_t *s, const char *ip, const uint8_t mac[6]) {
    arp_entry_t *e = &s->arp_entries[s->arp_count++];
    snprintf(e->ip, sizeof(e->ip), "%s", ip);
    memcpy(e->mac, mac, 6);
    snprintf(e->iface, sizeof(e->iface), "eth0");
}

static void add_dhcp(sloth_state_t *s, const char *ip, const char *host) {
    dhcp_lease_t *L = &s->dhcp_leases[s->dhcp_count++];
    snprintf(L->ip,       sizeof(L->ip),       "%s", ip);
    snprintf(L->hostname, sizeof(L->hostname), "%s", host);
}

static void add_probe(sloth_state_t *s, const uint8_t mac[6], const char *ssid,
                       int frames) {
    probe_client_t *p = &s->probe_clients[s->probe_count++];
    memcpy(p->mac, mac, 6);
    snprintf(p->ssid, sizeof(p->ssid), "%s", ssid);
    p->frame_count = frames;
    p->last_seen   = time(NULL);
}

static void add_beacon(sloth_state_t *s, const uint8_t bssid[6], int sig) {
    beacon_ap_t *b = &s->beacon_aps[s->beacon_count++];
    memcpy(b->bssid, bssid, 6);
    b->signal_dbm = (int8_t)sig;
    b->last_seen  = time(NULL);
}

static int find_by_mac(const sloth_state_t *s, const uint8_t mac[6]) {
    for (int i = 0; i < s->device_count; i++)
        if (memcmp(s->devices[i].mac, mac, 6) == 0) return i;
    return -1;
}

/* ── Basic upsert ────────────────────────────────────────── */

static void test_empty_state_yields_zero_devices(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    devices_update(&s);
    ASSERT_EQ(s.device_count, 0);
}

static void test_arp_creates_device(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac[6] = { 0xb8, 0x27, 0xeb, 0x11, 0x22, 0x33 };
    add_arp(&s, "192.168.1.100", mac);
    devices_update(&s);
    ASSERT_EQ(s.device_count, 1);
    ASSERT(find_by_mac(&s, mac) >= 0);
    ASSERT_STR(s.devices[0].ip, "192.168.1.100");
    ASSERT((s.devices[0].sources & DEV_SRC_ARP) != 0);
}

static void test_dhcp_attaches_hostname_via_arp_bridge(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac[6] = { 0xb8, 0x27, 0xeb, 0x11, 0x22, 0x33 };
    add_arp (&s, "192.168.1.100", mac);
    add_dhcp(&s, "192.168.1.100", "raspberrypi");
    devices_update(&s);
    int idx = find_by_mac(&s, mac);
    ASSERT(idx >= 0);
    ASSERT_STR(s.devices[idx].hostname, "raspberrypi");
    ASSERT((s.devices[idx].sources & DEV_SRC_DHCP) != 0);
}

static void test_dhcp_without_arp_does_not_create_device(void) {
    /* DHCP lacks a MAC, so it can only enrich devices already known via ARP. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    add_dhcp(&s, "192.168.1.100", "raspberrypi");
    devices_update(&s);
    ASSERT_EQ(s.device_count, 0);
}

static void test_beacon_marks_as_ap(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t bssid[6] = { 0xa4, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5 };
    add_beacon(&s, bssid, -55);
    devices_update(&s);
    int idx = find_by_mac(&s, bssid);
    ASSERT(idx >= 0);
    ASSERT_EQ(s.devices[idx].is_ap, 1);
    ASSERT_EQ(s.devices[idx].signal_dbm, -55);
    ASSERT((s.devices[idx].sources & DEV_SRC_BEACON) != 0);
}

static void test_probe_records_ssid_and_count(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };
    add_probe(&s, mac, "CoffeeShopWifi", 7);
    devices_update(&s);
    int idx = find_by_mac(&s, mac);
    ASSERT(idx >= 0);
    ASSERT_STR(s.devices[idx].last_ssid, "CoffeeShopWifi");
    ASSERT_EQ(s.devices[idx].probe_count, 7);
    ASSERT((s.devices[idx].sources & DEV_SRC_PROBE) != 0);
}

/* ── Cross-source dedup ──────────────────────────────────── */

static void test_arp_and_probe_share_one_device(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };
    add_arp  (&s, "192.168.1.50", mac);
    add_probe(&s, mac, "ssid", 3);
    devices_update(&s);
    ASSERT_EQ(s.device_count, 1);
    int idx = find_by_mac(&s, mac);
    ASSERT(idx >= 0);
    int srcs = s.devices[idx].sources;
    ASSERT((srcs & DEV_SRC_ARP)   != 0);
    ASSERT((srcs & DEV_SRC_PROBE) != 0);
}

static void test_distinct_macs_create_distinct_devices(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t a[6] = { 0xaa, 0,0,0,0, 1 };
    uint8_t b[6] = { 0xaa, 0,0,0,0, 2 };
    add_arp(&s, "192.168.1.10", a);
    add_arp(&s, "192.168.1.11", b);
    devices_update(&s);
    ASSERT_EQ(s.device_count, 2);
}

static void test_zero_mac_skipped(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t zero[6] = { 0, 0, 0, 0, 0, 0 };
    add_arp(&s, "192.168.1.99", zero);
    devices_update(&s);
    ASSERT_EQ(s.device_count, 0);
}

/* ── View ────────────────────────────────────────────────── */

static void test_view_draw_empty(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_devices_draw(&s);
    ASSERT(1);
}

static void test_view_draw_populated(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac1[6] = { 0xb8, 0x27, 0xeb, 0x11, 0x22, 0x33 };
    uint8_t mac2[6] = { 0xdc, 0xa6, 0x32, 0x00, 0x00, 0x01 };
    uint8_t bssid[6] = { 0xa4, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5 };
    add_arp   (&s, "192.168.1.100", mac1);
    add_arp   (&s, "192.168.1.101", mac2);
    add_dhcp  (&s, "192.168.1.100", "raspberrypi");
    add_beacon(&s, bssid, -42);
    devices_update(&s);
    ASSERT_EQ(s.device_count, 3);
    view_devices_draw(&s);
}

static void test_view_nav(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t a[6] = { 0xa, 0,0,0,0, 1 };
    uint8_t b[6] = { 0xa, 0,0,0,0, 2 };
    add_arp(&s, "192.168.1.1", a);
    add_arp(&s, "192.168.1.2", b);
    devices_update(&s);
    ASSERT_EQ(s.device_sel, 0);
    view_devices_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.device_sel, 1);
    view_devices_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.device_sel, 0);
    view_devices_key(&s, SLOTH_KEY_UP);   /* clamped */
    ASSERT_EQ(s.device_sel, 0);
}

void run_devices_tests(void) {
    TEST_SUITE("devices upsert");
    RUN_TEST(test_empty_state_yields_zero_devices);
    RUN_TEST(test_arp_creates_device);
    RUN_TEST(test_dhcp_attaches_hostname_via_arp_bridge);
    RUN_TEST(test_dhcp_without_arp_does_not_create_device);
    RUN_TEST(test_beacon_marks_as_ap);
    RUN_TEST(test_probe_records_ssid_and_count);

    TEST_SUITE("devices dedup");
    RUN_TEST(test_arp_and_probe_share_one_device);
    RUN_TEST(test_distinct_macs_create_distinct_devices);
    RUN_TEST(test_zero_mac_skipped);

    TEST_SUITE("view_devices");
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_populated);
    RUN_TEST(test_view_nav);
}
