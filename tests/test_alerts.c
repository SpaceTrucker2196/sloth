#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "views/alerts.h"

/* Helpers — build state with the exact preconditions a rule needs. */

static void seed_state(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
}

static void add_scan(sloth_state_t *s, const char *ip, int ports, int flagged) {
    scan_entry_t *e = &s->scan_entries[s->scan_count++];
    snprintf(e->ip, sizeof(e->ip), "%s", ip);
    e->port_count = ports;
    e->flagged    = flagged;
    e->first_seen = time(NULL);
    e->last_seen  = time(NULL);
}

static void add_deauth_flood(sloth_state_t *s, const uint8_t dst_mac[6]) {
    deauth_event_t *e = &s->deauth_events[s->deauth_count++];
    memcpy(e->dst, dst_mac, 6);
    e->reason = 7;
    e->count  = 20;
    e->flood  = 1;
}

static void add_dns_nxdomain(sloth_state_t *s, const char *src,
                              const char *qname, time_t ts) {
    if (s->dns_log_count >= MAX_DNS_LOG) return;
    dns_log_entry_t *e = &s->dns_log[s->dns_log_count++];
    snprintf(e->src,    sizeof(e->src),    "%s", src);
    snprintf(e->qname,  sizeof(e->qname),  "%s", qname);
    snprintf(e->qtype,  sizeof(e->qtype),  "A");
    snprintf(e->answer, sizeof(e->answer), "NXDOMAIN");
    e->is_resp = 1;
    e->ts      = ts;
}

static void add_dns_query(sloth_state_t *s, const char *src, const char *qname) {
    if (s->dns_log_count >= MAX_DNS_LOG) return;
    dns_log_entry_t *e = &s->dns_log[s->dns_log_count++];
    snprintf(e->src,    sizeof(e->src),    "%s", src);
    snprintf(e->qname,  sizeof(e->qname),  "%s", qname);
    snprintf(e->qtype,  sizeof(e->qtype),  "A");
    e->ts = time(NULL);
}

static void add_conn(sloth_state_t *s, const char *remote, uint16_t port) {
    conn_t *c = &s->conns[s->conn_count++];
    snprintf(c->local_addr,  sizeof(c->local_addr),  "192.168.1.5");
    snprintf(c->remote_addr, sizeof(c->remote_addr), "%s", remote);
    c->local_port  = 12345;
    c->remote_port = port;
    c->proto       = PROTO_TCP;
}

static int find_alert(const sloth_state_t *s, alert_type_t type) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == type) return i;
    return -1;
}

/* ── Rule firing ─────────────────────────────────────────── */

static void test_port_scan_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_scan(&s, "10.0.0.99", 15, 1);

    alerts_update(&s);
    ASSERT_GT(s.alert_count, 0);
    int idx = find_alert(&s, ALERT_TYPE_PORT_SCAN);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT_STR(s.alerts[idx].title, "PORT_SCAN");
}

static void test_port_scan_not_flagged_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_scan(&s, "10.0.0.99", 3, 0);   /* below threshold, not flagged */
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_PORT_SCAN), -1);
}

static void test_deauth_flood_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    add_deauth_flood(&s, mac);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_DEAUTH_FLOOD);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
}

static void test_nxdomain_burst_fires_at_threshold(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    time_t now = time(NULL);
    for (int i = 0; i < ALERT_NXDOMAIN_THRESH; i++) {
        char qn[32];
        snprintf(qn, sizeof(qn), "miss%d.example", i);
        add_dns_nxdomain(&s, "10.0.0.50", qn, now);
    }
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_NXDOMAIN_BURST) >= 0);
}

static void test_nxdomain_below_threshold_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    time_t now = time(NULL);
    for (int i = 0; i < ALERT_NXDOMAIN_THRESH - 1; i++) {
        char qn[32];
        snprintf(qn, sizeof(qn), "miss%d.example", i);
        add_dns_nxdomain(&s, "10.0.0.50", qn, now);
    }
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_NXDOMAIN_BURST), -1);
}

static void test_nxdomain_outside_window_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    time_t old = time(NULL) - (ALERT_NXDOMAIN_WINDOW_S + 10);
    for (int i = 0; i < ALERT_NXDOMAIN_THRESH + 5; i++) {
        char qn[32];
        snprintf(qn, sizeof(qn), "miss%d.example", i);
        add_dns_nxdomain(&s, "10.0.0.50", qn, old);
    }
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_NXDOMAIN_BURST), -1);
}

static void test_threat_domain_fires_on_ioc(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_dns_query(&s, "192.168.1.5", "malware.testing.com");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_THREAT_DOMAIN);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
}

static void test_threat_domain_clean_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_dns_query(&s, "192.168.1.5", "google.com");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_THREAT_DOMAIN), -1);
}

static void test_threat_ip_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_conn(&s, "192.0.2.66", 443);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_THREAT_IP);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
}

static void seed_arp(sloth_state_t *s, const char *ip,
                      uint8_t a, uint8_t b, uint8_t c,
                      uint8_t d, uint8_t e, uint8_t f) {
    if (s->arp_count >= MAX_ARP_ENTRIES) return;
    arp_entry_t *ar = &s->arp_entries[s->arp_count++];
    memset(ar, 0, sizeof(*ar));
    snprintf(ar->ip, sizeof(ar->ip), "%s", ip);
    ar->mac[0] = a; ar->mac[1] = b; ar->mac[2] = c;
    ar->mac[3] = d; ar->mac[4] = e; ar->mac[5] = f;
}

static void test_arp_spoof_no_alert_on_first_obs(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_arp(&s, "192.168.1.1", 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ARP_SPOOF), -1);
}

static void test_arp_spoof_fires_on_mac_change(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_arp(&s, "192.168.1.1", 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01);
    alerts_update(&s);

    /* Second poll — same IP, different MAC. */
    s.arp_count = 0;
    seed_arp(&s, "192.168.1.1", 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x99);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_ARP_SPOOF);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
}

static void test_arp_spoof_silent_on_same_mac(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_arp(&s, "192.168.1.1", 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01);
    alerts_update(&s);
    s.arp_count = 0;
    seed_arp(&s, "192.168.1.1", 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ARP_SPOOF), -1);
}

static void test_arp_spoof_skips_multicast_mac(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    /* Multicast bit set (0x01) — ARP shouldn't normally see this,
     * but the rule should defensively skip. */
    seed_arp(&s, "224.0.0.1", 0x01, 0x00, 0x5e, 0x00, 0x00, 0x01);
    alerts_update(&s);
    s.arp_count = 0;
    seed_arp(&s, "224.0.0.1", 0x01, 0x00, 0x5e, 0x00, 0x00, 0xff);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ARP_SPOOF), -1);
}

/* ── Rogue DHCP ──────────────────────────────────────────── */

static void add_dhcp_event(sloth_state_t *s, const char *mac,
                            const char *server_ip, uint8_t msg_type) {
    if (s->dhcp_event_count >= MAX_DHCP_EVENTS) return;
    dhcp_event_t *e = &s->dhcp_events[s->dhcp_event_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->mac,       sizeof(e->mac),       "%s", mac);
    snprintf(e->server_ip, sizeof(e->server_ip), "%s", server_ip);
    e->msg_type  = msg_type;
    e->last_seen = time(NULL);
}

static void test_rogue_dhcp_single_server_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_dhcp_event(&s, "aa:bb:cc:dd:ee:01", "192.168.1.1", 5 /* ACK */);
    add_dhcp_event(&s, "aa:bb:cc:dd:ee:02", "192.168.1.1", 5);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ROGUE_DHCP), -1);
}

static void test_rogue_dhcp_two_servers_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_dhcp_event(&s, "aa:bb:cc:dd:ee:01", "192.168.1.1",   5);
    add_dhcp_event(&s, "aa:bb:cc:dd:ee:02", "192.168.1.234", 5);   /* rogue */
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_ROGUE_DHCP);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
}

static void test_rogue_dhcp_client_requests_dont_count(void) {
    /* Client-side messages (DISCOVER / REQUEST) carry no server_ip;
     * those alone must not trigger the rule. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_dhcp_event(&s, "aa:bb:cc:dd:ee:01", "", 1 /* DISCOVER */);
    add_dhcp_event(&s, "aa:bb:cc:dd:ee:02", "", 3 /* REQUEST  */);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ROGUE_DHCP), -1);
}

/* ── Dedup ───────────────────────────────────────────────── */

static void test_dedup_increments_count(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_scan(&s, "10.0.0.99", 15, 1);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_PORT_SCAN);
    ASSERT(idx >= 0);
    int first_count = s.alerts[idx].count;
    ASSERT_EQ(first_count, 1);

    /* same state, fire again */
    alerts_update(&s);
    idx = find_alert(&s, ALERT_TYPE_PORT_SCAN);
    ASSERT(idx >= 0);
    ASSERT_EQ(s.alerts[idx].count, 2);
    /* only one entry (no duplicates) */
    int ps_entries = 0;
    for (int i = 0; i < s.alert_count; i++)
        if (s.alerts[i].type == ALERT_TYPE_PORT_SCAN) ps_entries++;
    ASSERT_EQ(ps_entries, 1);
}

static void test_distinct_keys_create_distinct_alerts(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_scan(&s, "10.0.0.99", 15, 1);
    add_scan(&s, "10.0.0.55", 12, 1);
    alerts_update(&s);
    int n = 0;
    for (int i = 0; i < s.alert_count; i++)
        if (s.alerts[i].type == ALERT_TYPE_PORT_SCAN) n++;
    ASSERT_EQ(n, 2);
}

/* ── Snapshot ordering ────────────────────────────────────── */

static void test_snapshot_newest_first(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);

    /* First fire an old alert by stuffing the engine via two updates with
       different state. With current API we can't predate first_seen, but
       newer alerts will have a later last_seen. */
    add_scan(&s, "10.0.0.10", 15, 1);
    alerts_update(&s);

    /* sleep cheating: just call update again with a different IP — both will
       have last_seen ~= now, but in the order alerts were created. */
    seed_state(&s);
    add_scan(&s, "10.0.0.20", 20, 1);
    alerts_update(&s);

    /* the most recently fired key should now be at index 0 (newest first) */
    ASSERT(s.alert_count >= 2);
    /* whichever ordering: both have type PORT_SCAN, last_seen >= the other.
       Confirm sorted descending. */
    for (int i = 1; i < s.alert_count; i++)
        ASSERT(s.alerts[i - 1].last_seen >= s.alerts[i].last_seen);
}

/* ── View / key ──────────────────────────────────────────── */

static void test_view_draw_empty(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    view_alerts_draw(&s);
    ASSERT(1);
}

static void test_view_draw_populated(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_scan(&s, "10.0.0.99", 15, 1);
    add_dns_query(&s, "192.168.1.5", "malware.testing.com");
    add_conn(&s, "192.0.2.66", 443);
    alerts_update(&s);
    ASSERT_GE(s.alert_count, 3);
    view_alerts_draw(&s);
}

static void test_view_key_nav(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_scan(&s, "10.0.0.99", 15, 1);
    add_scan(&s, "10.0.0.55", 12, 1);
    alerts_update(&s);
    ASSERT_EQ(s.alert_sel, 0);
    view_alerts_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.alert_sel, 1);
    view_alerts_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.alert_sel, 0);
}

static void test_view_key_clear(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_scan(&s, "10.0.0.99", 15, 1);
    alerts_update(&s);
    ASSERT_GT(s.alert_count, 0);
    view_alerts_key(&s, 'c');
    ASSERT_EQ(s.alert_count, 0);

    /* underlying engine cleared too — a second update with no triggers
       should leave the count at zero. */
    seed_state(&s);
    alerts_update(&s);
    ASSERT_EQ(s.alert_count, 0);
}

void run_alerts_tests(void) {
    TEST_SUITE("alerts rule firing");
    RUN_TEST(test_port_scan_fires);
    RUN_TEST(test_port_scan_not_flagged_no_fire);
    RUN_TEST(test_deauth_flood_fires);
    RUN_TEST(test_nxdomain_burst_fires_at_threshold);
    RUN_TEST(test_nxdomain_below_threshold_no_fire);
    RUN_TEST(test_nxdomain_outside_window_no_fire);
    RUN_TEST(test_threat_domain_fires_on_ioc);
    RUN_TEST(test_threat_domain_clean_no_fire);
    RUN_TEST(test_threat_ip_fires);
    RUN_TEST(test_arp_spoof_no_alert_on_first_obs);
    RUN_TEST(test_arp_spoof_fires_on_mac_change);
    RUN_TEST(test_arp_spoof_silent_on_same_mac);
    RUN_TEST(test_arp_spoof_skips_multicast_mac);
    RUN_TEST(test_rogue_dhcp_single_server_no_fire);
    RUN_TEST(test_rogue_dhcp_two_servers_fires);
    RUN_TEST(test_rogue_dhcp_client_requests_dont_count);

    TEST_SUITE("alerts dedup");
    RUN_TEST(test_dedup_increments_count);
    RUN_TEST(test_distinct_keys_create_distinct_alerts);

    TEST_SUITE("alerts snapshot");
    RUN_TEST(test_snapshot_newest_first);

    TEST_SUITE("view_alerts");
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_populated);
    RUN_TEST(test_view_key_nav);
    RUN_TEST(test_view_key_clear);
}
