#include <string.h>
#include <stdio.h>
#include "sloth.h"
#include "fake_platform.h"

fake_net_t g_fake_net;

void fake_net_reset(void) {
    memset(&g_fake_net, 0, sizeof(g_fake_net));
}

static int fake_get_ifaces(iface_stat_t *out, int max) {
    int n = g_fake_net.iface_count < max ? g_fake_net.iface_count : max;
    memcpy(out, g_fake_net.ifaces, (size_t)n * sizeof(iface_stat_t));
    return n;
}

static int fake_get_conns(conn_t *out, int max) {
    int n = g_fake_net.conn_count < max ? g_fake_net.conn_count : max;
    memcpy(out, g_fake_net.conns, (size_t)n * sizeof(conn_t));
    return n;
}

static int fake_wifi_scan(wifi_ap_t *out, int max) {
    int n = g_fake_net.ap_count < max ? g_fake_net.ap_count : max;
    memcpy(out, g_fake_net.aps, (size_t)n * sizeof(wifi_ap_t));
    return n;
}

static int fake_get_wifi_stations(wifi_sta_t *out, int max) {
    int n = g_fake_net.wifi_sta_count < max ? g_fake_net.wifi_sta_count : max;
    memcpy(out, g_fake_net.wifi_stas, (size_t)n * sizeof(wifi_sta_t));
    return n;
}

void fake_net_apply_probe(sloth_state_t *s) {
    int n = g_fake_net.probe_count < MAX_PROBE_CLIENTS
          ? g_fake_net.probe_count : MAX_PROBE_CLIENTS;
    memcpy(s->probe_clients, g_fake_net.probe_clients,
           (size_t)n * sizeof(probe_client_t));
    s->probe_count = n;
    snprintf(s->probe_iface, sizeof(s->probe_iface), "%s", g_fake_net.probe_iface);
}

static int fake_get_arp(arp_entry_t *out, int max) {
    (void)out; (void)max; return 0;
}

static int fake_get_dhcp(dhcp_lease_t *out, int max) {
    (void)out; (void)max; return 0;
}

static void fake_init(void)    {}
static void fake_cleanup(void) {}

/* Satisfies the extern in ntop.h — only compiled in the test binary */
platform_ops_t g_platform = {
    fake_get_ifaces,
    fake_get_conns,
    fake_wifi_scan,
    fake_get_wifi_stations,
    fake_get_arp,
    fake_get_dhcp,
    fake_init,
    fake_cleanup,
};
