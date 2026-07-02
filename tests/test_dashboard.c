#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "views/dashboard.h"

/* The dashboard view's draw path is mostly ncurses-positioned mvprintw
 * calls. In the test build those are stubbed, so we mostly verify:
 *   - draw is safe on empty / populated state
 *   - up/down nav drives s->conn_sel as designed */

static void seed_iface(sloth_state_t *s, const char *name) {
    if (s->iface_count >= MAX_IFACES) return;
    iface_stat_t *I = &s->ifaces[s->iface_count++];
    memset(I, 0, sizeof(*I));
    snprintf(I->name, sizeof(I->name), "%s", name);
    I->rx_rate = 1e6; I->tx_rate = 2e5;
    I->rx_bytes = (uint64_t)5 << 30;   /* 5 GB */
    I->tx_bytes = (uint64_t)1 << 30;

    /* Seed the rate history slot for this iface so the sparkline path
       exercises non-zero glyphs. */
    if (s->iface_count <= MAX_IFACES) {
        iface_hist_t *H = &s->iface_hist[s->iface_count - 1];
        snprintf(H->name, sizeof(H->name), "%s", name);
        H->head  = HIST_LEN / 2;
        H->count = HIST_LEN;
        for (int i = 0; i < HIST_LEN; i++) {
            /* triangle: 0 -> HIST_LEN -> 0, then a few zeros to exercise '_' */
            double v = (i < HIST_LEN / 2)
                       ? (double)i
                       : (double)(HIST_LEN - i);
            H->rx[i] = v * 1e5;
            H->tx[i] = v * 5e4;
            if (i % 5 == 0) H->rx[i] = 0;   /* sprinkle zeros */
        }
    }
}

static void seed_conn(sloth_state_t *s, const char *remote, uint16_t rport) {
    conn_t *c = &s->conns[s->conn_count++];
    memset(c, 0, sizeof(*c));
    snprintf(c->local_addr,  sizeof(c->local_addr),  "192.168.1.5");
    snprintf(c->remote_addr, sizeof(c->remote_addr), "%s", remote);
    snprintf(c->proc, sizeof(c->proc), "chrome");
    c->local_port  = 33445;
    c->remote_port = rport;
    c->proto       = PROTO_TCP;
    c->state       = 1;
    c->pid         = 1234;
}

static void seed_ap(sloth_state_t *s, const char *ssid, int sig, int ch) {
    wifi_ap_t *a = &s->aps[s->ap_count++];
    memset(a, 0, sizeof(*a));
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    a->signal_dbm = sig;
    a->channel = ch;
}

static void seed_probe(sloth_state_t *s, const uint8_t mac[6],
                       const char *ssid, int sig) {
    probe_client_t *p = &s->probe_clients[s->probe_count++];
    memset(p, 0, sizeof(*p));
    memcpy(p->mac, mac, 6);
    snprintf(p->ssid, sizeof(p->ssid), "%s", ssid);
    p->signal_dbm = (int8_t)sig;
}

static void seed_packet(sloth_state_t *s, const char *src, const char *dst,
                        uint16_t sport, uint16_t dport, const char *info) {
    if (s->pkt_count >= MAX_PACKETS) return;
    int slot = s->pkt_head;
    packet_info_t *p = &s->packets[slot];
    memset(p, 0, sizeof(*p));
    snprintf(p->src, sizeof(p->src), "%s", src);
    snprintf(p->dst, sizeof(p->dst), "%s", dst);
    snprintf(p->info, sizeof(p->info), "%s", info);
    p->src_port = sport;
    p->dst_port = dport;
    p->proto    = PROTO_TCP;
    p->ts_sec   = 1700000000;
    s->pkt_head = (s->pkt_head + 1) % MAX_PACKETS;
    if (s->pkt_count < MAX_PACKETS) s->pkt_count++;
}

static void seed_mdns(sloth_state_t *s, const char *instance, uint16_t port) {
    if (s->mdns_count >= MAX_MDNS_SERVICES) return;
    mdns_service_t *m = &s->mdns_services[s->mdns_count++];
    memset(m, 0, sizeof(*m));
    snprintf(m->instance, sizeof(m->instance), "%s", instance);
    snprintf(m->service,  sizeof(m->service),  "_http._tcp");
    m->port = port;
}

static void seed_dhcp_event(sloth_state_t *s, const char *ip,
                            const char *host, uint8_t msg) {
    if (s->dhcp_event_count >= MAX_DHCP_EVENTS) return;
    dhcp_event_t *e = &s->dhcp_events[s->dhcp_event_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->ip,       sizeof(e->ip),       "%s", ip);
    snprintf(e->hostname, sizeof(e->hostname), "%s", host);
    e->msg_type = msg;
}

static void seed_ssdp(sloth_state_t *s, const char *ip, const char *type) {
    if (s->ssdp_count >= MAX_SSDP_DEVICES) return;
    ssdp_device_t *d = &s->ssdp_devices[s->ssdp_count++];
    memset(d, 0, sizeof(*d));
    snprintf(d->ip,   sizeof(d->ip),   "%s", ip);
    snprintf(d->type, sizeof(d->type), "%s", type);
}

static void seed_arp(sloth_state_t *s, const char *ip,
                     const uint8_t mac[6]) {
    if (s->arp_count >= MAX_ARP_ENTRIES) return;
    arp_entry_t *a = &s->arp_entries[s->arp_count++];
    memset(a, 0, sizeof(*a));
    snprintf(a->ip, sizeof(a->ip), "%s", ip);
    memcpy(a->mac, mac, 6);
    snprintf(a->iface, sizeof(a->iface), "eth0");
}

static void seed_dns_log(sloth_state_t *s, const char *qname,
                         const char *answer, int is_resp) {
    if (s->dns_log_count >= MAX_DNS_LOG) return;
    dns_log_entry_t *e = &s->dns_log[s->dns_log_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->qname,  sizeof(e->qname),  "%s", qname);
    snprintf(e->qtype,  sizeof(e->qtype),  "A");
    snprintf(e->answer, sizeof(e->answer), "%s", answer);
    snprintf(e->src,    sizeof(e->src),    "192.168.1.5");
    e->is_resp = is_resp;
}

static void seed_icmp_log(sloth_state_t *s, const char *src, const char *desc,
                          int is_v6) {
    if (s->icmp_log_count >= MAX_ICMP_LOG) return;
    icmp_log_entry_t *e = &s->icmp_log[s->icmp_log_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->src,  sizeof(e->src),  "%s", src);
    snprintf(e->dst,  sizeof(e->dst),  "8.8.8.8");
    snprintf(e->desc, sizeof(e->desc), "%s", desc);
    e->is_v6 = (uint8_t)is_v6;
}

static void seed_deauth(sloth_state_t *s, const uint8_t dst[6],
                        uint16_t reason, int flood) {
    if (s->deauth_count >= MAX_DEAUTH_ENTRIES) return;
    deauth_event_t *e = &s->deauth_events[s->deauth_count++];
    memset(e, 0, sizeof(*e));
    memcpy(e->dst, dst, 6);
    e->reason = reason;
    e->count  = 12;
    e->flood  = flood;
}

static void seed_beacon(sloth_state_t *s, const char *ssid, int sig, int ch) {
    beacon_ap_t *b = &s->beacon_aps[s->beacon_count++];
    memset(b, 0, sizeof(*b));
    snprintf(b->ssid, sizeof(b->ssid), "%s", ssid);
    b->signal_dbm = (int8_t)sig;
    b->channel    = ch;
}

/* ── Smoke ───────────────────────────────────────────────── */

static void test_draw_empty(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_dashboard_draw(&s);
    ASSERT(1);
}

static void test_draw_populated(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_iface(&s, "eth0");
    seed_iface(&s, "wlan0");
    seed_conn(&s, "142.250.80.46", 443);
    seed_conn(&s, "1.1.1.1",       443);
    seed_packet(&s, "192.168.1.5", "1.1.1.1",       33445, 443, "TLS handshake");
    seed_packet(&s, "1.1.1.1",     "192.168.1.5",   443,   33445, "ACK");
    seed_ap(&s, "home_5g",       -42, 36);
    seed_ap(&s, "neighbor_24",   -67, 11);
    uint8_t mac1[6] = { 0xde,0xad,0xbe,0xef,0x00,0x01 };
    uint8_t mac2[6] = { 0xde,0xad,0xbe,0xef,0x00,0x02 };
    seed_probe(&s, mac1, "Starbucks", -55);
    seed_probe(&s, mac2, "",          -71);
    seed_beacon(&s, "home_5g",     -42, 36);
    seed_beacon(&s, "neighbor_24", -67, 11);
    seed_mdns(&s, "My Printer._ipp._tcp", 631);
    seed_mdns(&s, "Apple TV._airplay._tcp", 7000);
    seed_dhcp_event(&s, "192.168.1.100", "raspberrypi", 5);
    seed_dhcp_event(&s, "192.168.1.101", "laptop",      3);
    seed_ssdp(&s, "192.168.1.1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2");
    uint8_t arp_mac[6] = { 0xb8, 0x27, 0xeb, 0x11, 0x22, 0x33 };
    seed_arp(&s, "192.168.1.100", arp_mac);
    uint8_t deauth_dst[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    seed_deauth(&s, deauth_dst, 7, 1);
    seed_dns_log(&s, "example.com",     "93.184.216.34", 1);
    seed_dns_log(&s, "missing.example", "NXDOMAIN",      1);
    seed_dns_log(&s, "google.com",      "",              0);
    seed_icmp_log(&s, "192.168.1.5", "Echo Req",    0);
    seed_icmp_log(&s, "8.8.8.8",     "Echo Reply",  0);
    seed_icmp_log(&s, "fe80::1",     "Neigh Sol",   1);
    view_dashboard_draw(&s);
    ASSERT(1);
}

/* ── iface hide election (shared with iface view) ────────── */

static void test_iface_is_hidden_matches(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snprintf(s.iface_hidden[0], sizeof(s.iface_hidden[0]), "docker0");
    snprintf(s.iface_hidden[1], sizeof(s.iface_hidden[1]), "veth0abc");
    s.iface_hidden_count = 2;
    ASSERT_EQ(iface_is_hidden(&s, "docker0"),  1);
    ASSERT_EQ(iface_is_hidden(&s, "veth0abc"), 1);
    ASSERT_EQ(iface_is_hidden(&s, "eth0"),     0);
    ASSERT_EQ(iface_is_hidden(&s, "wlan0"),    0);
}

static void test_iface_is_hidden_empty(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ASSERT_EQ(iface_is_hidden(&s, "eth0"), 0);
}

static void test_dashboard_draws_with_hidden_iface(void) {
    /* Populate two visible + one hidden. Smoke test: the band must not
     * crash on the filter branch. Behavioural verification of the row
     * count lives in the iface-view tests; here we're guarding the
     * draw path. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_iface(&s, "eth0");
    seed_iface(&s, "docker0");
    seed_iface(&s, "wlan0");
    snprintf(s.iface_hidden[0], sizeof(s.iface_hidden[0]), "docker0");
    s.iface_hidden_count = 1;
    view_dashboard_draw(&s);
    ASSERT_EQ(iface_is_hidden(&s, "docker0"), 1);
    ASSERT_EQ(iface_is_hidden(&s, "eth0"),    0);
}

/* ── Navigation ──────────────────────────────────────────── */

static void test_nav_scrolls_conn_sel(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    for (int i = 0; i < 5; i++) seed_conn(&s, "1.2.3.4", (uint16_t)(443 + i));
    ASSERT_EQ(s.conn_sel, 0);
    view_dashboard_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.conn_sel, 1);
    view_dashboard_key(&s, SLOTH_KEY_DOWN);
    view_dashboard_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.conn_sel, 3);
    view_dashboard_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.conn_sel, 2);
}

static void test_nav_clamps_at_top(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_conn(&s, "1.2.3.4", 443);
    s.conn_sel = 0;
    view_dashboard_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.conn_sel, 0);
}

static void test_nav_clamps_at_bottom(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_conn(&s, "1.2.3.4", 443);
    seed_conn(&s, "5.6.7.8", 443);
    s.conn_sel = 1;
    view_dashboard_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.conn_sel, 1);
}

static void test_nav_empty_state(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.conn_sel = 0;
    view_dashboard_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.conn_sel, 0);
    view_dashboard_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.conn_sel, 0);
}

void run_dashboard_tests(void) {
    TEST_SUITE("dashboard draw");
    RUN_TEST(test_draw_empty);
    RUN_TEST(test_draw_populated);
    RUN_TEST(test_iface_is_hidden_matches);
    RUN_TEST(test_iface_is_hidden_empty);
    RUN_TEST(test_dashboard_draws_with_hidden_iface);

    TEST_SUITE("dashboard nav");
    RUN_TEST(test_nav_scrolls_conn_sel);
    RUN_TEST(test_nav_clamps_at_top);
    RUN_TEST(test_nav_clamps_at_bottom);
    RUN_TEST(test_nav_empty_state);
}
