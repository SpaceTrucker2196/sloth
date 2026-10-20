#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "sensor_health.h"
#include "probe_pnl.h"
#include "alerts.h"
#include "top_hosts.h"
#include "devices.h"
#include "beacon_snoop.h"
#include "seqnum_track.h"
#include "assoc_track.h"
#include "dns_log.h"
#include "tls_log.h"
#include "quic_log.h"
#include "http_log.h"
#include "ntp_log.h"
#include "icmp_log.h"
#include "dns.h"
#include <fcntl.h>
#include <unistd.h>
#include <sqlite3.h>

/* ── Table-overflow accounting — issue #91 slice 3 ──────────
 *
 * Every bounded table in sloth discards observations when it fills, and
 * until now did so invisibly: a sensor at max occupancy and a sensor on
 * a quiet segment produced the same empty delta. The tally is what makes
 * "not observing" separable from "nothing to observe".
 *
 * The first block is pure counter logic — no radio, no capture. The
 * second drives the real modules past their caps with hand-seeded state,
 * because a counter nobody calls reads as a permanently healthy sensor. */

/* Read a whole text file; the doc-pin test compares prose to the
 * compiled enum. Path is repo-root relative, as elsewhere in the suite. */
static char *slurp_text(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

static void test_tally_starts_at_zero(void) {
    sh_evict_reset();
    ASSERT_EQ((int)sh_evict_total(), 0);
    for (int k = 0; k < SH_EVICT_KIND_COUNT; k++)
        ASSERT_EQ((int)sh_evict_count((sh_evict_t)k), 0);
}

static void test_tally_counts_per_kind(void) {
    sh_evict_reset();
    sh_evict_note(SH_EVICT_ALERT);
    sh_evict_note(SH_EVICT_ALERT);
    sh_evict_note(SH_EVICT_PNL_SSID);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_ALERT),    2);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_PNL_SSID), 1);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_TOP_HOST), 0);
    ASSERT_EQ((int)sh_evict_total(),                  3);
}

static void test_tally_is_monotonic(void) {
    /* Lifetime, never decremented: a counter that clears has no meaning
     * to a consumer sampling it twice. */
    sh_evict_reset();
    for (int i = 0; i < 100; i++) sh_evict_note(SH_EVICT_DEVICE);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_DEVICE), 100);
    sh_evict_note(SH_EVICT_DEVICE);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_DEVICE), 101);
}

static void test_tally_ignores_out_of_range_kinds(void) {
    sh_evict_reset();
    sh_evict_note((sh_evict_t)SH_EVICT_KIND_COUNT);
    sh_evict_note((sh_evict_t)-1);
    sh_evict_note((sh_evict_t)9999);
    ASSERT_EQ((int)sh_evict_total(), 0);
    ASSERT_EQ((int)sh_evict_count((sh_evict_t)-1), 0);
}

static void test_evict_names_are_stable_and_distinct(void) {
    /* Part of the `sensor_health` JSONL contract. */
    ASSERT_STR(sh_evict_name(SH_EVICT_ALERT),       "alert");
    ASSERT_STR(sh_evict_name(SH_EVICT_TOP_HOST),    "top_host");
    ASSERT_STR(sh_evict_name(SH_EVICT_PNL_CLIENT),  "pnl_client");
    ASSERT_STR(sh_evict_name(SH_EVICT_PNL_SSID),    "pnl_ssid");
    ASSERT_STR(sh_evict_name(SH_EVICT_DHCP_EVENT),  "dhcp_event");
    ASSERT_STR(sh_evict_name(SH_EVICT_EAP_SESSION), "eap_session");
    ASSERT_STR(sh_evict_name(SH_EVICT_DEVICE),      "device");
    ASSERT_STR(sh_evict_name(SH_EVICT_BEACON_AP),     "beacon_ap");
    ASSERT_STR(sh_evict_name(SH_EVICT_SEQNUM_CLIENT), "seqnum_client");
    ASSERT_STR(sh_evict_name(SH_EVICT_ASSOC_PAIR),    "assoc_pair");
    ASSERT_STR(sh_evict_name(SH_EVICT_ASSOC_REQ),     "assoc_req");
    ASSERT_STR(sh_evict_name(SH_EVICT_WPS_SESSION),   "wps_session");
    ASSERT_STR(sh_evict_name(SH_EVICT_EVIDENCE_FRAME), "evidence_frame");
    ASSERT_STR(sh_evict_name(SH_EVICT_PROBE_CLIENT),   "probe_client");
    ASSERT_STR(sh_evict_name(SH_EVICT_DNS_LOG),  "dns_log");
    ASSERT_STR(sh_evict_name(SH_EVICT_TLS_LOG),  "tls_log");
    ASSERT_STR(sh_evict_name(SH_EVICT_QUIC_LOG), "quic_log");
    ASSERT_STR(sh_evict_name(SH_EVICT_HTTP_LOG), "http_log");
    ASSERT_STR(sh_evict_name(SH_EVICT_NTP_LOG),  "ntp_log");
    ASSERT_STR(sh_evict_name(SH_EVICT_ICMP_LOG), "icmp_log");
    ASSERT_STR(sh_evict_name(SH_EVICT_RF_CHANNEL), "rf_channel");
    ASSERT_STR(sh_evict_name(SH_EVICT_HTTP_FLOW),  "http_flow");
    ASSERT_STR(sh_evict_name(SH_EVICT_BGP_SESSION), "bgp_session");
    ASSERT_STR(sh_evict_name(SH_EVICT_LDAP_EVENT),  "ldap_event");
    ASSERT_STR(sh_evict_name(SH_EVICT_KERB_EVENT),  "kerb_event");
    ASSERT_STR(sh_evict_name(SH_EVICT_SMB_SESSION), "smb_session");
    ASSERT_STR(sh_evict_name(SH_EVICT_SSH_FLOW),    "ssh_flow");
    ASSERT_STR(sh_evict_name(SH_EVICT_RDP_FLOW),    "rdp_flow");
    ASSERT_STR(sh_evict_name(SH_EVICT_SNMP_FLOW),   "snmp_flow");
    ASSERT_STR(sh_evict_name(SH_EVICT_MQTT_FLOW),   "mqtt_flow");
    ASSERT_STR(sh_evict_name(SH_EVICT_MDNS_SERVICE), "mdns_service");
    ASSERT_STR(sh_evict_name(SH_EVICT_NBNS_NAME),   "nbns_name");
    ASSERT_STR(sh_evict_name(SH_EVICT_ARP_HIST),    "arp_hist");
    ASSERT_STR(sh_evict_name(SH_EVICT_FRAG_BSS),     "frag_bss");
    ASSERT_STR(sh_evict_name(SH_EVICT_FRAG_STA),     "frag_sta");
    ASSERT_STR(sh_evict_name(SH_EVICT_FRAG_SESSION), "frag_session");
    ASSERT_STR(sh_evict_name(SH_EVICT_FRAG_ASSOC),   "frag_assoc");
    ASSERT_STR(sh_evict_name(SH_EVICT_FRAG_MPDU),    "frag_mpdu");
    ASSERT_STR(sh_evict_name(SH_EVICT_NDP_RA),       "ndp_ra");
    ASSERT_STR(sh_evict_name(SH_EVICT_ROGUE_RADIUS), "rogue_radius");
    ASSERT_STR(sh_evict_name(SH_EVICT_SSDP_DEVICE),  "ssdp_device");
    ASSERT_STR(sh_evict_name(SH_EVICT_ONVIF_DEVICE), "onvif_device");
    ASSERT_STR(sh_evict_name(SH_EVICT_SMTP_FLOW),    "smtp_flow");
    ASSERT_STR(sh_evict_name(SH_EVICT_EAPOL_PENDING), "eapol_pending");
    ASSERT_STR(sh_evict_name(SH_EVICT_DEAUTH_OBS),    "deauth_obs");
    ASSERT_STR(sh_evict_name(SH_EVICT_DEAUTH_VICTIM), "deauth_victim");
    /* #143's pair appended after the #110 set, same rule. */
    ASSERT_EQ((int)SH_EVICT_DEAUTH_OBS, (int)SH_EVICT_EAPOL_PENDING + 1);
    /* Appended, never inserted: the first new kind sits right after the
     * last one the previous slice published, so every earlier evict_*
     * field keeps its position in the record. */
    ASSERT_EQ((int)SH_EVICT_FRAG_BSS, (int)SH_EVICT_ARP_HIST + 1);
    ASSERT_STR(sh_evict_name((sh_evict_t)SH_EVICT_KIND_COUNT), "");
    /* Names must be distinct: two kinds sharing one `evict_<name>` field
     * would silently merge two tables' loss into one number, which is the
     * coverage ambiguity the breakout exists to remove. */
    for (int a = 0; a < SH_EVICT_KIND_COUNT; a++)
        for (int b = a + 1; b < SH_EVICT_KIND_COUNT; b++)
            ASSERT(strcmp(sh_evict_name((sh_evict_t)a),
                          sh_evict_name((sh_evict_t)b)) != 0);
    /* Every kind must have a name — an unnamed bucket emits "" into the
     * record, which a consumer reads as a missing field. */
    for (int k = 0; k < SH_EVICT_KIND_COUNT; k++)
        ASSERT(sh_evict_name((sh_evict_t)k)[0] != '\0');
}

/* ── wiring: real tables must reach the tally ─────────────── */

static void test_pnl_ssid_overflow_is_counted(void) {
    /* MAX_PNL_SSIDS_PER_CLI SSIDs fit; the next shifts the oldest out. */
    probe_pnl_clear();
    sh_evict_reset();
    uint8_t mac[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
    char ssid[40];
    for (int i = 0; i < MAX_PNL_SSIDS_PER_CLI; i++) {
        snprintf(ssid, sizeof(ssid), "net-%d", i);
        probe_pnl_observe(mac, ssid, "", "");
    }
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_PNL_SSID), 0);   /* still fits */
    probe_pnl_observe(mac, "one-too-many", "", "");
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_PNL_SSID), 1);
    probe_pnl_clear();
}

static void test_pnl_client_overflow_is_counted(void) {
    probe_pnl_clear();
    sh_evict_reset();
    uint8_t mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
    for (int i = 0; i < MAX_PNL_CLIENTS; i++) {
        mac[4] = (uint8_t)((i >> 8) & 0xff);
        mac[5] = (uint8_t)(i & 0xff);
        probe_pnl_observe(mac, "shared-ssid", "", "");
    }
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_PNL_CLIENT), 0);
    mac[3] = 0xff; mac[4] = 0xff; mac[5] = 0xff;
    probe_pnl_observe(mac, "shared-ssid", "", "");
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_PNL_CLIENT), 1);
    probe_pnl_clear();
}

static void test_top_host_overflow_is_counted(void) {
    /* Public addresses only — the table ignores private, loopback,
     * link-local and multicast, so 10.x would never reach the cap. */
    top_hosts_clear();
    sh_evict_reset();
    sloth_state_t *s = calloc(1, sizeof(*s));
    ASSERT(s != NULL);
    if (!s) return;
    int n = 200;   /* comfortably past the internal TOP_HOSTS_CAP */
    for (int i = 0; i < n; i++) {
        conn_t *c = &s->conns[i];
        snprintf(c->local_addr,  sizeof(c->local_addr),  "192.168.1.2");
        snprintf(c->remote_addr, sizeof(c->remote_addr), "8.%d.%d.%d",
                 (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        c->remote_port = 443;
        c->proto       = 6;
    }
    s->conn_count = n;
    top_hosts_update(s);
    ASSERT_GT((int)sh_evict_count(SH_EVICT_TOP_HOST), 0);
    top_hosts_clear();
    free(s);
}

static void test_device_table_refusal_is_counted(void) {
    /* devices.c refuses a NEW device when full rather than evicting one.
     * Different mechanism, same sensor-health meaning: an observation did
     * not make it into the table. ARP alone fills it exactly, so the
     * beacons behind it are what get refused. */
    sloth_state_t *s = calloc(1, sizeof(*s));
    ASSERT(s != NULL);
    if (!s) return;
    sh_evict_reset();
    for (int i = 0; i < MAX_ARP_ENTRIES; i++) {
        arp_entry_t *a = &s->arp_entries[i];
        snprintf(a->ip, sizeof(a->ip), "10.%d.%d.%d",
                 (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        a->mac[0] = 0x02;
        a->mac[4] = (uint8_t)((i >> 8) & 0xff);
        a->mac[5] = (uint8_t)(i & 0xff);
        snprintf(a->iface, sizeof(a->iface), "eth0");
    }
    s->arp_count = MAX_ARP_ENTRIES;
    for (int i = 0; i < 4; i++) {
        beacon_ap_t *b = &s->beacon_aps[i];
        b->bssid[0] = 0x06;            /* distinct from every ARP MAC above */
        b->bssid[5] = (uint8_t)i;
        snprintf(b->ssid, sizeof(b->ssid), "ap-%d", i);
        b->channel = 6;
    }
    s->beacon_count = 4;
    devices_update(s);
    ASSERT_EQ(s->device_count, MAX_DEVICES);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_DEVICE), 4);
    free(s);
}

static void test_alert_overflow_is_counted(void) {
    /* More distinct weak-TLS sources than MAX_ALERTS holds; each fires
     * its own dedup key, so the engine must start evicting. */
    alerts_clear();
    sh_evict_reset();
    sloth_state_t *s = calloc(1, sizeof(*s));
    ASSERT(s != NULL);
    if (!s) return;
    for (int i = 0; i < MAX_TLS_LOG; i++) {
        tls_log_entry_t *e = &s->tls_log[i];
        snprintf(e->src,     sizeof(e->src),     "203.0.%d.%d",
                 (i >> 8) & 0xff, i & 0xff);
        snprintf(e->dst,     sizeof(e->dst),     "198.51.100.1");
        snprintf(e->tls_ver, sizeof(e->tls_ver), "TLS 1.0");
        e->ts = 1700000000;
    }
    s->tls_log_count = MAX_TLS_LOG;
    alerts_update(s);
    ASSERT_GT((int)sh_evict_count(SH_EVICT_ALERT), 0);
    alerts_clear();
    free(s);
}

/* ââ wiring: beacon / seqnum / assoc tables (#91 wave 6) âââ */

static void test_beacon_table_overflow_is_counted(void) {
    beacon_clear();
    sh_evict_reset();
    uint8_t bssid[6] = {0x02, 0, 0, 0, 0, 0};
    for (int i = 0; i < MAX_BEACON_APS + 3; i++) {
        bssid[4] = (uint8_t)(i >> 8);
        bssid[5] = (uint8_t)i;
        beacon_record(bssid, "net", -40, 6, "wpa2", 100, NULL);
    }
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_BEACON_AP), 3);
    /* Updating a known AP must not evict. */
    beacon_record(bssid, "net", -40, 6, "wpa2", 100, NULL);
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_BEACON_AP), 3);
    beacon_clear();
    sh_evict_reset();
}

static void test_seqnum_table_overflow_is_counted(void) {
    seqnum_clear();
    sh_evict_reset();
    uint8_t mac[6] = {0x02, 1, 0, 0, 0, 0};
    for (int i = 0; i < MAX_SEQNUM_CLIENTS + 2; i++) {
        mac[4] = (uint8_t)(i >> 8);
        mac[5] = (uint8_t)i;
        seqnum_track_observe_at(mac, (uint16_t)i, (time_t)(1000 + i));
    }
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_SEQNUM_CLIENT), 2);
    seqnum_track_observe_at(mac, 9, (time_t)9999);   /* known: no evict */
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_SEQNUM_CLIENT), 2);
    seqnum_clear();
    sh_evict_reset();
}

static void test_assoc_tables_overflow_is_counted(void) {
    assoc_clear();
    sh_evict_reset();
    uint8_t bssid[6] = {0x02, 2, 0, 0, 0, 0};
    uint8_t sta[6]   = {0x02, 3, 0, 0, 0, 0};
    for (int i = 0; i < MAX_ASSOC_ENTRIES + 4; i++) {
        sta[4] = (uint8_t)(i >> 8);
        sta[5] = (uint8_t)i;
        assoc_observe(bssid, sta, "net", 0, -40, 6);
    }
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_ASSOC_PAIR), 4);
    /* Re-observing a resident pair must not evict. */
    assoc_observe(bssid, sta, "net", 0, -40, 6);
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_ASSOC_PAIR), 4);
    assoc_clear();
    sh_evict_reset();
}

static void test_assoc_request_table_overflow_is_counted(void) {
    assoc_clear();
    sh_evict_reset();
    assoc_req_t req;
    memset(&req, 0, sizeof(req));
    req.bssid[0] = 0x02;
    req.sta[0]   = 0x02;
    for (int i = 0; i < MAX_ASSOC_ENTRIES + 2; i++) {
        req.sta[4] = (uint8_t)(i >> 8);
        req.sta[5] = (uint8_t)i;
        req.ts     = (time_t)(1000 + i);
        assoc_request_observe(&req, -40, 6);
    }
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_ASSOC_REQ), 2);
    assoc_clear();
    sh_evict_reset();
}

/* ── wiring: the six per-protocol flow rings ──────────────
 *
 * These were the last uncounted family in the tally. Each is a plain
 * circular buffer, so a record is lost at exactly one moment: the append
 * that lands on a ring already holding MAX entries overwrites the oldest.
 *
 * Driven through each module's own record API, as the beacon / seqnum /
 * assoc cases above are. The entry is the ring's input — bytes are the
 * parser's input, and the parser has its own hand-built-frame suite per
 * ring. One parser-fed case follows this one so the whole
 * frame → parse → record → tally path is pinned too, not just the ring.
 *
 * Every ring's cap is MAX_*_LOG; the thunk varies a field per record so
 * a mistaken de-duplication somewhere could not make the fill look like
 * one entry repeated. */

static void rec_dns(int i) {
    dns_log_entry_t e;
    memset(&e, 0, sizeof(e));
    snprintf(e.src,   sizeof(e.src),   "198.51.100.%d", i & 0xff);
    snprintf(e.qname, sizeof(e.qname), "q%d.example.com", i);
    snprintf(e.qtype, sizeof(e.qtype), "A");
    e.ts = (time_t)(1700000000 + i);
    dns_log_record(&e);
}

static void rec_tls(int i) {
    tls_log_entry_t e;
    memset(&e, 0, sizeof(e));
    snprintf(e.src,     sizeof(e.src),     "198.51.100.%d", i & 0xff);
    snprintf(e.dst,     sizeof(e.dst),     "203.0.113.1");
    snprintf(e.host,    sizeof(e.host),    "h%d.example.com", i);
    snprintf(e.tls_ver, sizeof(e.tls_ver), "TLS 1.3");
    e.ts = (time_t)(1700000000 + i);
    tls_log_record(&e);
}

static void rec_quic(int i) {
    quic_log_entry_t e;
    memset(&e, 0, sizeof(e));
    snprintf(e.src,  sizeof(e.src),  "198.51.100.%d", i & 0xff);
    snprintf(e.dst,  sizeof(e.dst),  "203.0.113.2");
    snprintf(e.host, sizeof(e.host), "q%d.example.com", i);
    snprintf(e.ver,  sizeof(e.ver),  "v1");
    e.ts = (time_t)(1700000000 + i);
    quic_log_record(&e);
}

static void rec_http(int i) {
    http_log_entry_t e;
    memset(&e, 0, sizeof(e));
    /* One fixed 4-tuple on purpose. http_log_record() opens a pairing
     * window per *flow* (#71), and that flow table is a separate bounded
     * table; varying the tuple would churn it and confuse what this case
     * is measuring with what it is not. */
    snprintf(e.src,    sizeof(e.src),    "198.51.100.9");
    snprintf(e.dst,    sizeof(e.dst),    "203.0.113.3");
    snprintf(e.method, sizeof(e.method), "GET");
    snprintf(e.host,   sizeof(e.host),   "example.com");
    snprintf(e.path,   sizeof(e.path),   "/p%d", i);
    e.src_port       = 44000;
    e.dst_port       = 80;
    e.content_length = -1;
    e.ts = (time_t)(1700000000 + i);
    http_log_record(&e);
}

static void rec_ntp(int i) {
    ntp_log_entry_t e;
    memset(&e, 0, sizeof(e));
    snprintf(e.src,  sizeof(e.src),  "198.51.100.%d", i & 0xff);
    snprintf(e.dst,  sizeof(e.dst),  "203.0.113.4");
    snprintf(e.mode, sizeof(e.mode), "client");
    snprintf(e.ref,  sizeof(e.ref),  "GPS");
    e.version = 4;
    e.stratum = 2;
    e.ts = (time_t)(1700000000 + i);
    ntp_log_record(&e);
}

static void rec_icmp(int i) {
    icmp_log_entry_t e;
    memset(&e, 0, sizeof(e));
    snprintf(e.src,  sizeof(e.src),  "198.51.100.%d", i & 0xff);
    snprintf(e.dst,  sizeof(e.dst),  "203.0.113.5");
    snprintf(e.desc, sizeof(e.desc), "Echo Req");
    e.type = 8;
    e.seq  = (uint16_t)i;
    e.ts   = (time_t)(1700000000 + i);
    icmp_log_record(&e);
}

typedef struct {
    sh_evict_t kind;
    int        cap;
    void     (*record)(int i);
    void     (*clear)(void);
} flow_ring_case_t;

static const flow_ring_case_t FLOW_RINGS[] = {
    { SH_EVICT_DNS_LOG,  MAX_DNS_LOG,  rec_dns,  dns_log_clear  },
    { SH_EVICT_TLS_LOG,  MAX_TLS_LOG,  rec_tls,  tls_log_clear  },
    { SH_EVICT_QUIC_LOG, MAX_QUIC_LOG, rec_quic, quic_log_clear },
    { SH_EVICT_HTTP_LOG, MAX_HTTP_LOG, rec_http, http_log_clear },
    { SH_EVICT_NTP_LOG,  MAX_NTP_LOG,  rec_ntp,  ntp_log_clear  },
    { SH_EVICT_ICMP_LOG, MAX_ICMP_LOG, rec_icmp, icmp_log_clear },
};
#define FLOW_RING_COUNT ((int)(sizeof(FLOW_RINGS) / sizeof(FLOW_RINGS[0])))

static void test_flow_ring_fill_to_cap_is_not_a_loss(void) {
    /* The decisive case. Filling a ring to exactly MAX overwrites
     * nothing, so the tally must still read zero. Reading occupancy
     * AFTER the append — the boundary defect `6c1e3a9` found in the
     * probe table — counts one here instead of none, and a tally that
     * reports loss on a table that is merely filling is worse than no
     * tally, because every sensor would look lossy from its first
     * minute. */
    for (int r = 0; r < FLOW_RING_COUNT; r++) {
        const flow_ring_case_t *c = &FLOW_RINGS[r];
        c->clear();
        sh_evict_reset();
        for (int i = 0; i < c->cap; i++) c->record(i);
        if (sh_evict_count(c->kind) != 0)
            fprintf(stderr, "    %s counted %llu evictions after exactly "
                            "%d records — it should count none\n",
                    sh_evict_name(c->kind),
                    (unsigned long long)sh_evict_count(c->kind), c->cap);
        ASSERT_EQ((long long)sh_evict_count(c->kind), 0);
        ASSERT_EQ((long long)sh_evict_total(), 0);
        c->clear();
    }
    sh_evict_reset();
}

static void test_flow_ring_overwrite_is_counted(void) {
    for (int r = 0; r < FLOW_RING_COUNT; r++) {
        const flow_ring_case_t *c = &FLOW_RINGS[r];
        c->clear();
        sh_evict_reset();
        for (int i = 0; i < c->cap; i++) c->record(i);

        c->record(c->cap);                 /* oldest entry is gone */
        ASSERT_EQ((long long)sh_evict_count(c->kind), 1);

        for (int i = 1; i < 10; i++) c->record(c->cap + i);
        ASSERT_EQ((long long)sh_evict_count(c->kind), 10);

        /* Nothing else moved: one ring overflowing must not be
         * attributable to another table. */
        ASSERT_EQ((long long)sh_evict_total(), 10);
        c->clear();
    }
    sh_evict_reset();
}

static void test_flow_ring_clear_restores_empty_occupancy(void) {
    /* `*_log_clear()` empties the ring, so the fill that follows it has
     * room again and loses nothing — while the lifetime tally keeps the
     * losses already recorded, because a counter that clears has no
     * meaning to a consumer sampling it twice. */
    for (int r = 0; r < FLOW_RING_COUNT; r++) {
        const flow_ring_case_t *c = &FLOW_RINGS[r];
        c->clear();
        sh_evict_reset();
        for (int i = 0; i < c->cap + 3; i++) c->record(i);
        ASSERT_EQ((long long)sh_evict_count(c->kind), 3);

        c->clear();
        for (int i = 0; i < c->cap; i++) c->record(i);
        ASSERT_EQ((long long)sh_evict_count(c->kind), 3);
        c->clear();
    }
    sh_evict_reset();
}

static void test_flow_ring_snapshot_still_caps_at_max(void) {
    /* The tally must not have changed what the ring hands the views: a
     * ring driven past its cap still snapshots exactly MAX newest-first
     * entries, and the newest is the last one recorded. */
    sloth_state_t *s = calloc(1, sizeof(*s));
    ASSERT(s != NULL);
    if (!s) return;
    dns_log_clear();
    sh_evict_reset();
    for (int i = 0; i < MAX_DNS_LOG + 7; i++) rec_dns(i);
    dns_log_snapshot(s);
    ASSERT_EQ(s->dns_log_count, MAX_DNS_LOG);
    char newest[DNS_NAME_LEN];
    snprintf(newest, sizeof(newest), "q%d.example.com", MAX_DNS_LOG + 6);
    ASSERT_STR(s->dns_log[0].qname, newest);
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_DNS_LOG), 7);
    dns_log_clear();
    sh_evict_reset();
    free(s);
}

static void test_flow_rings_are_classified_apart_from_tables(void) {
    /* Exactly the six rings, and nothing else. A synthesis table
     * misclassified as a ring would vanish from the faults-only strip
     * and from the change-only JSONL signature — it would stop being
     * reported as news, which is the whole point of counting it. */
    int rings = 0;
    for (int k = 0; k < SH_EVICT_KIND_COUNT; k++) {
        if (sh_evict_is_flow_ring((sh_evict_t)k)) rings++;
    }
    ASSERT_EQ(rings, FLOW_RING_COUNT);
    for (int r = 0; r < FLOW_RING_COUNT; r++)
        ASSERT(sh_evict_is_flow_ring(FLOW_RINGS[r].kind));

    ASSERT(!sh_evict_is_flow_ring(SH_EVICT_ALERT));
    ASSERT(!sh_evict_is_flow_ring(SH_EVICT_DEVICE));
    ASSERT(!sh_evict_is_flow_ring(SH_EVICT_PROBE_CLIENT));
    ASSERT(!sh_evict_is_flow_ring(SH_EVICT_EVIDENCE_FRAME));
    /* Both tables added on 2026-10-13 are bounded working sets, not
     * circular buffers: neither rolls over as a matter of course, so a
     * non-zero count is a lost measurement and belongs in the subtotal
     * that drives the strip and the signature. */
    ASSERT(!sh_evict_is_flow_ring(SH_EVICT_RF_CHANNEL));
    ASSERT(!sh_evict_is_flow_ring(SH_EVICT_HTTP_FLOW));
}

static void test_table_subtotal_excludes_flow_rings(void) {
    /* The two totals answer different questions: "did this sensor lose
     * an observation" vs "did anything roll over at all". */
    sh_evict_reset();
    ASSERT_EQ((long long)sh_evict_total_tables(), 0);

    for (int i = 0; i < 5; i++) sh_evict_note(SH_EVICT_DNS_LOG);
    for (int i = 0; i < 4; i++) sh_evict_note(SH_EVICT_ICMP_LOG);
    /* Nine rolled-over view records are not nine lost observations. */
    ASSERT_EQ((long long)sh_evict_total(),        9);
    ASSERT_EQ((long long)sh_evict_total_tables(), 0);

    sh_evict_note(SH_EVICT_DEVICE);
    sh_evict_note(SH_EVICT_BEACON_AP);
    ASSERT_EQ((long long)sh_evict_total(),        11);
    ASSERT_EQ((long long)sh_evict_total_tables(), 2);
    sh_evict_reset();
}

static void test_flow_ring_overflow_counted_through_the_parser(void) {
    /* The ring cases above start from an entry struct. This one starts
     * from bytes, so the path an actual capture takes — frame → parse →
     * record → tally — is pinned end to end.
     *
     * Hand-built DNS query per RFC 1035 §4.1: a 12-byte header followed
     * by one question. No capture, no fixture. */
    static const uint8_t QUERY[] = {
        0x12, 0x34,              /* ID                                   */
        0x01, 0x00,              /* QR=0 OPCODE=0 RD=1                   */
        0x00, 0x01,              /* QDCOUNT = 1                          */
        0x00, 0x00,              /* ANCOUNT = 0                          */
        0x00, 0x00,              /* NSCOUNT = 0                          */
        0x00, 0x00,              /* ARCOUNT = 0                          */
        /* QNAME "a.example" — length-prefixed labels, root terminator   */
        0x01, 'a',
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x00,
        0x00, 0x01,              /* QTYPE  = A                           */
        0x00, 0x01               /* QCLASS = IN                          */
    };

    dns_log_clear();
    sh_evict_reset();

    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(QUERY, (int)sizeof(QUERY), "198.51.100.23", &e), 1);
    ASSERT_STR(e.qname, "a.example");

    for (int i = 0; i < MAX_DNS_LOG; i++) dns_log_record(&e);
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_DNS_LOG), 0);
    dns_log_record(&e);
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_DNS_LOG), 1);

    dns_log_clear();
    sh_evict_reset();
}

/* The schema doc tells an operator which quiet tables are trustworthy
 * silence and which are unmeasured, so its counted list is part of the
 * contract — and it went stale the moment the 802.11 tables joined the
 * tally, because nobody re-read the prose. Pin it: every kind the build
 * counts must appear in the doc's counted list, so adding a kind without
 * documenting it fails here instead of misleading a consumer. */
static void test_schema_doc_lists_every_counted_table(void) {
    char *doc = slurp_text("docs/wiki/jsonl-schema.md");
    ASSERT(doc != NULL);
    if (!doc) return;

    /* Parse the one delimited list rather than searching the section.
     * The looser form this replaces — substring anywhere between the
     * heading and "**Not** counted:" — was shown in review to pass with
     * `wps_session` deleted from the authoritative list, because the
     * name also occurs in the prose that follows it inside the same
     * bounds. Exact set comparison, both directions. */
    const char *start = strstr(doc, "and this is the whole set:");
    ASSERT(start != NULL);
    if (!start) { free(doc); return; }
    start += strlen("and this is the whole set:");
    const char *end = strstr(start, ". ");
    ASSERT(end != NULL);
    if (!end) { free(doc); return; }

    /* Every backticked token in that span is a claimed counted kind. */
    int seen[SH_EVICT_KIND_COUNT];
    for (int k = 0; k < SH_EVICT_KIND_COUNT; k++) seen[k] = 0;
    int doc_names = 0, unknown = 0;
    for (const char *q = start; q < end; ) {
        const char *a = memchr(q, '`', (size_t)(end - q));
        if (!a) break;
        const char *b = memchr(a + 1, '`', (size_t)(end - a - 1));
        if (!b) break;
        size_t nlen = (size_t)(b - a - 1);
        doc_names++;
        int matched = 0;
        for (int k = 0; k < SH_EVICT_KIND_COUNT; k++) {
            const char *nm = sh_evict_name((sh_evict_t)k);
            if (strlen(nm) == nlen && strncmp(nm, a + 1, nlen) == 0) {
                seen[k] = 1; matched = 1; break;
            }
        }
        if (!matched) {
            unknown++;
            fprintf(stderr, "    jsonl-schema.md counts `%.*s`, which is "
                            "not an sh_evict_t kind\n", (int)nlen, a + 1);
        }
        q = b + 1;
    }

    /* doc subset of enum: a stale or invented name is a false coverage
       claim, which is the failure this prose exists to prevent. */
    ASSERT_EQ(unknown, 0);
    /* enum subset of doc: adding a kind without documenting it would
       otherwise mislead a consumer reading the list as complete. */
    for (int k = 0; k < SH_EVICT_KIND_COUNT; k++) {
        if (!seen[k])
            fprintf(stderr, "    sh_evict_t counts %s; jsonl-schema.md's "
                            "list omits it\n", sh_evict_name((sh_evict_t)k));
        ASSERT(seen[k]);
    }
    /* The list is exactly the enum, not a superset that happens to
       contain it. */
    ASSERT_EQ(doc_names, (int)SH_EVICT_KIND_COUNT);

    /* The uncounted side must still refuse to read as full coverage:
     * prose listing only what IS counted implies the rest is loss-free.
     *
     * Asserted structurally rather than by naming an example. This
     * assertion used to require the literal "probe_client" there,
     * because that table was the example when it was written — and on
     * 2026-10-08 probe_client became counted, so the test failed on a
     * change that was correct. A test that has to be edited every time
     * a table graduates is a test that will one day be edited wrongly.
     *
     * What holds regardless: no sh_evict_t name may appear on the
     * uncounted side, because a kind cannot be both, and the
     * "not all loss" caveat has to survive. */
    /* Bounded to the uncounted PARAGRAPH, not the rest of the file:
       searching to EOF swept in later sections that legitimately name
       counted kinds, so the first version of this loop reported
       wps_session and evidence_frame as contradictions when the prose
       was correct — it had been scanning from the end of the COUNTED
       list, not from the uncounted marker, so it swept the sentence
       that legitimately explains which 802.11 tables joined the tally. */
    const char *nc = strstr(doc, "**Not** counted:");
    ASSERT(nc != NULL);
    if (!nc) { free(doc); return; }
    const char *para_end = strstr(nc, "\n\n");
    size_t para_len = para_end ? (size_t)(para_end - nc) : strlen(nc);
    for (int k = 0; k < SH_EVICT_KIND_COUNT; k++) {
        char quoted[64];
        snprintf(quoted, sizeof(quoted), "`%s`", sh_evict_name((sh_evict_t)k));
        const char *hit = strstr(nc, quoted);
        if (hit && (size_t)(hit - nc) < para_len) {
            fprintf(stderr, "    jsonl-schema.md lists %s as NOT counted "
                            "while sh_evict_t counts it\n",
                    sh_evict_name((sh_evict_t)k));
            ASSERT(hit == NULL);
        }
    }
    ASSERT(strstr(end, "not \"all loss\"") != NULL);
    free(doc);
}

/* ── Parse-fault tally (#126) ────────────────────────────────
 *
 * The sibling of the eviction tally. Pure counter logic first; the
 * wiring tests live beside each parser (test_beacon_snoop.c,
 * test_capture_path.c, …) because that is where the frame is built. */

static void test_parse_fault_tally_counts_per_kind(void) {
    sh_parse_fault_reset();
    ASSERT_EQ((int)sh_parse_fault_total(), 0);
    for (int k = 0; k < SH_PF_KIND_COUNT; k++)
        ASSERT_EQ((int)sh_parse_fault_count((sh_parse_fault_t)k), 0);
    sh_parse_fault_note(SH_PF_IE_OVERRUN);
    sh_parse_fault_note(SH_PF_IE_OVERRUN);
    sh_parse_fault_note(SH_PF_DOT11_RUNT);
    ASSERT_EQ((int)sh_parse_fault_count(SH_PF_IE_OVERRUN), 2);
    ASSERT_EQ((int)sh_parse_fault_count(SH_PF_DOT11_RUNT), 1);
    ASSERT_EQ((int)sh_parse_fault_count(SH_PF_RADIOTAP_BAD), 0);
    ASSERT_EQ((int)sh_parse_fault_total(), 3);
    sh_parse_fault_reset();
    ASSERT_EQ((int)sh_parse_fault_total(), 0);
}

static void test_parse_fault_ignores_out_of_range_kinds(void) {
    sh_parse_fault_reset();
    sh_parse_fault_note((sh_parse_fault_t)SH_PF_KIND_COUNT);
    sh_parse_fault_note((sh_parse_fault_t)-1);
    sh_parse_fault_note((sh_parse_fault_t)9999);
    ASSERT_EQ((int)sh_parse_fault_total(), 0);
    ASSERT_EQ((int)sh_parse_fault_count((sh_parse_fault_t)-1), 0);
    ASSERT_STR(sh_parse_fault_name((sh_parse_fault_t)SH_PF_KIND_COUNT), "");
    ASSERT_EQ(sh_parse_fault_is_wired((sh_parse_fault_t)SH_PF_KIND_COUNT), 0);
}

/* The two tallies are separate stores. A parse fault landing in the
 * eviction sum would change what the published `evictions` field means
 * — the reason the issue made this a sibling enum and not more kinds. */
static void test_parse_faults_do_not_reach_the_eviction_tally(void) {
    sh_evict_reset();
    sh_parse_fault_reset();
    for (int k = 0; k < SH_PF_KIND_COUNT; k++)
        sh_parse_fault_note((sh_parse_fault_t)k);
    ASSERT_EQ((int)sh_parse_fault_total(), (int)SH_PF_KIND_COUNT);
    ASSERT_EQ((int)sh_evict_total(), 0);
    sh_evict_note(SH_EVICT_ALERT);
    ASSERT_EQ((int)sh_parse_fault_total(), (int)SH_PF_KIND_COUNT);
    sh_parse_fault_reset();
    ASSERT_EQ((int)sh_evict_total(), 1);
    sh_evict_reset();
}

static void test_parse_fault_names_are_stable_and_distinct(void) {
    /* Part of the `sensor_health` JSONL contract (`parse_fault_<name>`),
     * in enum order — which is emission order. */
    ASSERT_STR(sh_parse_fault_name(SH_PF_RADIOTAP_BAD),  "radiotap_bad");
    ASSERT_STR(sh_parse_fault_name(SH_PF_DOT11_RUNT),    "dot11_runt");
    ASSERT_STR(sh_parse_fault_name(SH_PF_IE_OVERRUN),    "ie_overrun");
    ASSERT_STR(sh_parse_fault_name(SH_PF_RSN_MALFORMED), "rsn_malformed");
    ASSERT_STR(sh_parse_fault_name(SH_PF_MLE_MALFORMED), "mle_malformed");
    ASSERT_STR(sh_parse_fault_name(SH_PF_IP_TRUNCATED),  "ip_truncated");
    ASSERT_STR(sh_parse_fault_name(SH_PF_IP_FRAGMENT),   "ip_fragment");
    ASSERT_STR(sh_parse_fault_name(SH_PF_DNS_NAME_BAD),  "dns_name_bad");
    ASSERT_STR(sh_parse_fault_name(SH_PF_TLS_MALFORMED), "tls_malformed");
    ASSERT_STR(sh_parse_fault_name(SH_PF_FRAME_EDGE),    "frame_edge");
    ASSERT_EQ((int)SH_PF_KIND_COUNT, 10);
    for (int a = 0; a < SH_PF_KIND_COUNT; a++) {
        ASSERT(sh_parse_fault_name((sh_parse_fault_t)a)[0] != '\0');
        for (int b = a + 1; b < SH_PF_KIND_COUNT; b++)
            ASSERT(strcmp(sh_parse_fault_name((sh_parse_fault_t)a),
                          sh_parse_fault_name((sh_parse_fault_t)b)) != 0);
    }
}

/* Which kinds have a writer. Pinned so that wiring a kind is a visible
 * edit here and in the schema doc, and so a reserved kind cannot be
 * mistaken for a measured one: its 0 means "not measured". */
static void test_parse_fault_wired_set(void) {
    ASSERT_EQ(sh_parse_fault_is_wired(SH_PF_RADIOTAP_BAD),  1);
    ASSERT_EQ(sh_parse_fault_is_wired(SH_PF_DOT11_RUNT),    1);
    ASSERT_EQ(sh_parse_fault_is_wired(SH_PF_IE_OVERRUN),    1);
    ASSERT_EQ(sh_parse_fault_is_wired(SH_PF_RSN_MALFORMED), 1);
    ASSERT_EQ(sh_parse_fault_is_wired(SH_PF_MLE_MALFORMED), 1);
    ASSERT_EQ(sh_parse_fault_is_wired(SH_PF_IP_TRUNCATED),  1);
    ASSERT_EQ(sh_parse_fault_is_wired(SH_PF_IP_FRAGMENT),   1);
    ASSERT_EQ(sh_parse_fault_is_wired(SH_PF_DNS_NAME_BAD),  0);
    ASSERT_EQ(sh_parse_fault_is_wired(SH_PF_TLS_MALFORMED), 0);
    ASSERT_EQ(sh_parse_fault_is_wired(SH_PF_FRAME_EDGE),    1);
}

/* beacon_parse_ies() is the first walk on the iterator (#126). One
 * element that overruns adds exactly one IE_OVERRUN — not one per
 * element skipped, not one per output, and nothing to any other kind.
 * Elements per IEEE 802.11-2020 §9.4.2.1: SSID (0) "lab", then a DS
 * Parameter Set (3) claiming 9 body octets with 1 present. */
static void test_beacon_ie_overrun_reaches_the_parse_fault_tally(void) {
    static const uint8_t ies[] = { 0x00, 0x03, 'l', 'a', 'b',
                                   0x03, 0x09, 0x06 };
    char ssid[33]; char enc[10]; int ch = 0;
    beacon_rsn_t rsn;
    sh_parse_fault_reset();
    beacon_parse_ies(ies, (int)sizeof ies, 0, 0, ssid, &ch, enc, &rsn, NULL);
    ASSERT_EQ((int)sh_parse_fault_count(SH_PF_IE_OVERRUN), 1);
    ASSERT_EQ((int)sh_parse_fault_total(), 1);
    /* The element before the fault was still read, and the per-BSSID
       counter MGMT_FUZZ scores from moved with it. */
    ASSERT_STR(ssid, "lab");
    ASSERT_EQ(rsn.ie_overruns, 1);
    sh_parse_fault_reset();
}

/* A list that tiles exactly adds nothing. Without this the test above
 * would pass for a walker that tallied every call. */
static void test_beacon_clean_ies_add_no_parse_fault(void) {
    static const uint8_t ies[] = { 0x00, 0x03, 'l', 'a', 'b',
                                   0x03, 0x01, 0x06 };
    char ssid[33]; char enc[10]; int ch = 0;
    beacon_rsn_t rsn;
    sh_parse_fault_reset();
    beacon_parse_ies(ies, (int)sizeof ies, 0, 0, ssid, &ch, enc, &rsn, NULL);
    ASSERT_EQ(ch, 6);
    ASSERT_EQ((int)sh_parse_fault_total(), 0);
    ASSERT_EQ(rsn.ie_overruns, 0);
}

/* A one-octet tail cannot be an element header. It is a fault, so the
 * sensor-wide tally counts it; it is NOT an element whose length ran
 * off the end, which is all `ie_overruns` has ever counted, so that
 * per-BSSID field — and the MGMT_FUZZ score and IE-order fingerprint
 * that read it — stay where they were before #126. */
static void test_beacon_one_byte_tail_is_tallied_not_scored(void) {
    static const uint8_t ies[] = { 0x00, 0x03, 'l', 'a', 'b', 0xdd };
    char ssid[33]; char enc[10]; int ch = 0;
    beacon_rsn_t rsn;
    sh_parse_fault_reset();
    beacon_parse_ies(ies, (int)sizeof ies, 0, 0, ssid, &ch, enc, &rsn, NULL);
    ASSERT_STR(ssid, "lab");
    ASSERT_EQ((int)sh_parse_fault_count(SH_PF_IE_OVERRUN), 1);
    ASSERT_EQ(rsn.ie_overruns, 0);
    ASSERT(rsn.fp.ie_order_hash != 0);
    sh_parse_fault_reset();
}

/* Collect the backticked names in the span after `marker` up to the
 * next ". ", and compare them to a predicate over the enum both ways. */
static void doc_list_matches(const char *doc, const char *marker,
                             int want_wired_only) {
    const char *start = strstr(doc, marker);
    ASSERT(start != NULL);
    if (!start) return;
    start += strlen(marker);
    const char *end = strstr(start, ". ");
    ASSERT(end != NULL);
    if (!end) return;
    int seen[SH_PF_KIND_COUNT];
    for (int k = 0; k < SH_PF_KIND_COUNT; k++) seen[k] = 0;
    int unknown = 0;
    for (const char *q = start; q < end; ) {
        const char *a = memchr(q, '`', (size_t)(end - q));
        if (!a) break;
        const char *b = memchr(a + 1, '`', (size_t)(end - a - 1));
        if (!b) break;
        size_t nlen = (size_t)(b - a - 1);
        int matched = 0;
        for (int k = 0; k < SH_PF_KIND_COUNT; k++) {
            const char *nm = sh_parse_fault_name((sh_parse_fault_t)k);
            if (strlen(nm) == nlen && strncmp(nm, a + 1, nlen) == 0) {
                seen[k]++; matched = 1; break;
            }
        }
        if (!matched) {
            unknown++;
            fprintf(stderr, "    jsonl-schema.md lists `%.*s` after \"%s\", "
                            "which is not an sh_parse_fault_t kind\n",
                    (int)nlen, a + 1, marker);
        }
        q = b + 1;
    }
    ASSERT_EQ(unknown, 0);
    for (int k = 0; k < SH_PF_KIND_COUNT; k++) {
        int want = want_wired_only
                 ? sh_parse_fault_is_wired((sh_parse_fault_t)k) : 1;
        if (seen[k] != want)
            fprintf(stderr, "    jsonl-schema.md: `%s` listed %d time(s) "
                            "after \"%s\", expected %d\n",
                    sh_parse_fault_name((sh_parse_fault_t)k), seen[k],
                    marker, want);
        ASSERT_EQ(seen[k], want);
    }
}

/* The doc states both the whole set and the measured subset; a kind
 * added, renamed or wired without the doc moving fails here. */
static void test_schema_doc_lists_every_parse_fault_kind(void) {
    char *doc = slurp_text("docs/wiki/jsonl-schema.md");
    ASSERT(doc != NULL);
    if (!doc) return;
    doc_list_matches(doc, "the whole parse-fault set:", 0);
    doc_list_matches(doc, "Measured in this build:", 1);
    free(doc);
}

/* ── Process memory sample (#121) ──────────────────────────────
 *
 * The parse is pinned against hand-built status text in the shape
 * proc_pid_status(5) documents, so field extraction is proven without
 * trusting whatever this host's kernel prints. The live block then
 * checks the sampler against sentinels the test plants itself (an fd
 * it opens, SQLite memory it allocates), never an absolute figure: a
 * CI VM's RSS is not a number a test can know. */

/* Copy into an allocation of exactly `n` bytes with no terminator, so
 * a parser reading one byte past `len` is an ASan failure, not luck. */
static char *exact_copy(const char *text, int n) {
    char *b = malloc((size_t)n);
    if (b) memcpy(b, text, (size_t)n);
    return b;
}

static void test_mem_parse_status_reads_rss_and_hwm(void) {
    /* VmPeak and VmSize come first and carry larger values; a
     * prefix-loose match would pick them up instead. */
    static const char st[] =
        "Name:\tsloth\n"
        "State:\tS (sleeping)\n"
        "VmPeak:\t  912340 kB\n"
        "VmSize:\t  901112 kB\n"
        "VmHWM:\t   49124 kB\n"
        "VmRSS:\t   48580 kB\n"
        "RssAnon:\t   39576 kB\n"
        "Threads:\t3\n";
    int n = (int)sizeof(st) - 1;
    char *b = exact_copy(st, n);
    ASSERT(b != NULL);
    if (!b) return;
    long long rss = 0, hwm = 0;
    sh_mem_parse_status(b, n, &rss, &hwm);
    ASSERT_EQ(rss, 48580LL);
    ASSERT_EQ(hwm, 49124LL);
    free(b);
}

static void test_mem_parse_status_absent_is_unmeasured(void) {
    /* A kernel thread's status has no Vm* lines at all. -1, not 0: a 0
     * would read as "measured, nothing resident". */
    static const char st[] = "Name:\tkworker/0:1\nState:\tI (idle)\nThreads:\t1\n";
    long long rss = 0, hwm = 0;
    sh_mem_parse_status(st, (int)sizeof(st) - 1, &rss, &hwm);
    ASSERT_EQ(rss, -1LL);
    ASSERT_EQ(hwm, -1LL);
    rss = hwm = 0;
    sh_mem_parse_status(NULL, 10, &rss, &hwm);
    ASSERT_EQ(rss, -1LL);
    ASSERT_EQ(hwm, -1LL);
    rss = hwm = 0;
    sh_mem_parse_status(st, 0, &rss, &hwm);
    ASSERT_EQ(rss, -1LL);
    ASSERT_EQ(hwm, -1LL);
}

static void test_mem_parse_status_rejects_non_numbers(void) {
    static const char bad[] = "VmRSS:\t -5 kB\nVmHWM:\tabc kB\n";
    long long rss = 0, hwm = 0;
    sh_mem_parse_status(bad, (int)sizeof(bad) - 1, &rss, &hwm);
    ASSERT_EQ(rss, -1LL);
    ASSERT_EQ(hwm, -1LL);
    /* A key sharing the prefix, or holding it mid-line, is not the
     * field: the colon is part of the key, and keys start a line. The
     * first line is shaped so a five-byte "VmRSS" match would land
     * exactly on the digits. */
    static const char lookalike[] = "VmRSSx\t 77 kB\nXVmHWM:\t 88 kB\n";
    rss = hwm = 0;
    sh_mem_parse_status(lookalike, (int)sizeof(lookalike) - 1, &rss, &hwm);
    ASSERT_EQ(rss, -1LL);
    ASSERT_EQ(hwm, -1LL);
    /* Twenty digits overflow a long long: refused, not wrapped. */
    static const char huge[] = "VmRSS:\t99999999999999999999 kB\n";
    rss = 0;
    sh_mem_parse_status(huge, (int)sizeof(huge) - 1, &rss, &hwm);
    ASSERT_EQ(rss, -1LL);
}

static void test_mem_parse_status_stops_at_len(void) {
    /* The figure lies past `len`; the read must not reach it. The exact
     * allocation makes an over-read a sanitiser failure as well. */
    static const char st[] = "VmHWM:\t 12 kB\nVmRSS:\t 4096 kB\n";
    int cut = (int)(strstr(st, "4096") - st);   /* ends at "VmRSS:\t " */
    char *b = exact_copy(st, cut);
    ASSERT(b != NULL);
    if (!b) return;
    long long rss = 0, hwm = 0;
    sh_mem_parse_status(b, cut, &rss, &hwm);
    ASSERT_EQ(hwm, 12LL);
    ASSERT_EQ(rss, -1LL);
    free(b);
}

static void test_mem_sample_reads_this_process(void) {
    sh_mem_t m;
    sh_mem_sample(&m);
    /* Signs and orderings, not values: a live process has resident
     * pages, and one status read reports VmHWM >= VmRSS by construction
     * (the kernel folds current RSS into the peak it prints). */
    ASSERT_GT(m.rss_kb, 0LL);
    ASSERT_GE(m.rss_hwm_kb, m.rss_kb);
    ASSERT_GE(m.fd_count, 0LL);
    ASSERT_GE(m.sqlite_mem_kb, 0LL);          /* the test build has SQLite */
    ASSERT_GE(m.sqlite_mem_hwm_kb, m.sqlite_mem_kb);
}

static void test_mem_sample_counts_an_opened_fd(void) {
    sh_mem_t before, after, closed;
    sh_mem_sample(&before);
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(fd >= 0);
    if (fd < 0) return;
    sh_mem_sample(&after);
    ASSERT_EQ(after.fd_count - before.fd_count, 1LL);
    /* open() returns the lowest free slot, so 0..fd are all open and the
     * count is at least fd + 1 — a floor that catches undercounting.
     * Excluding the sampler's own directory descriptor is a constant
     * offset that no delta can see and no ceiling can pin without
     * knowing every descriptor the runner holds; it is not claimed. */
    ASSERT_GE(after.fd_count, (long long)fd + 1);
    close(fd);
    sh_mem_sample(&closed);
    ASSERT_EQ(closed.fd_count, before.fd_count);
}

static void test_mem_sample_follows_sqlite_allocator(void) {
    sh_mem_t before, after, freed;
    sh_mem_sample(&before);
    void *p = sqlite3_malloc(4 << 20);
    ASSERT(p != NULL);
    if (!p) return;
    sh_mem_sample(&after);
    ASSERT_GE(after.sqlite_mem_kb - before.sqlite_mem_kb, 4096LL);
    ASSERT_GE(after.sqlite_mem_hwm_kb, after.sqlite_mem_kb);
    sqlite3_free(p);
    sh_mem_sample(&freed);
    /* Current falls back; the high-water mark keeps the peak. */
    ASSERT_LT(freed.sqlite_mem_kb, after.sqlite_mem_kb);
    ASSERT_GE(freed.sqlite_mem_hwm_kb, after.sqlite_mem_kb);
}

/* Any sanitizer that replaces the allocator hides this test's malloc
 * from glibc's mallinfo2(). ASan was the only one covered at first; the
 * CI TSan job then failed the growth assertion on 93cbfd0 because TSan
 * intercepts malloc too. MSan does the same. (The macro keeps its name
 * so the call sites below read unchanged.) */
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define SH_TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || \
    __has_feature(memory_sanitizer)
#define SH_TEST_ASAN 1
#endif
#endif

static void test_mem_sample_follows_glibc_malloc(void) {
    sh_mem_t before;
    sh_mem_sample(&before);
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
    ASSERT_GE(before.malloc_kb, 0LL);
#ifndef SH_TEST_ASAN
    /* 8 MiB is past glibc's mmap threshold, so it lands in hblkhd
     * whether or not it is touched. */
    sh_mem_t after;
    char *p = malloc(8u << 20);
    ASSERT(p != NULL);
    if (!p) return;
    p[0] = 1;
    sh_mem_sample(&after);
    ASSERT_GE(after.malloc_kb - before.malloc_kb, 8192LL);
    free(p);
#else
    /* Under ASan the sanitiser owns malloc and mallinfo2() never sees a
     * block this test allocates, so only presence is checkable here;
     * the delta is asserted by the unsanitised run. */
    fprintf(stderr, "    (ASan build: malloc_kb delta not checkable)\n");
#endif
#else
    ASSERT_EQ(before.malloc_kb, -1LL);
#endif
}

static void test_mem_sample_reports_resolver_counter(void) {
    /* No test performs a real getnameinfo(3) — the suite is passive and
     * offline — so this pins the wiring to src/dns.c's counter at its
     * one reachable value: 0 after a reset, under a request the default
     * policy suppresses. A non-zero value is not exercised here. */
    dns_resolver_reset_policy();
    dns_resolver_stats_reset();
    char host[DNS_NAME_MAX];
    (void)dns_resolve("192.0.2.1", host, sizeof(host));
    sh_mem_t m;
    sh_mem_sample(&m);
    dns_resolver_stats_t ds;
    dns_resolver_stats(&ds);
    ASSERT_GE((long long)ds.resolve_requests, 1LL);
    ASSERT_EQ(m.resolver_calls, (long long)ds.getnameinfo_calls);
    ASSERT_EQ(m.resolver_calls, 0LL);
    dns_resolver_stats_reset();
}

static const char *const k_mem_fields[] = {
    "rss_kb", "rss_hwm_kb", "sqlite_mem_kb", "sqlite_mem_hwm_kb",
    "malloc_kb", "fd_count", "resolver_calls",
};

static void test_schema_doc_lists_every_memory_field(void) {
    char *doc = slurp_text("docs/wiki/jsonl-schema.md");
    ASSERT(doc != NULL);
    if (!doc) return;
    for (size_t i = 0; i < sizeof(k_mem_fields) / sizeof(k_mem_fields[0]); i++) {
        char key[64];
        snprintf(key, sizeof(key), "`%s`", k_mem_fields[i]);
        int found = strstr(doc, key) != NULL;
        if (!found)
            fprintf(stderr, "    jsonl-schema.md does not document %s\n", key);
        ASSERT(found);
    }
    free(doc);
}

void run_sensor_health_tests(void) {
    TEST_SUITE("sensor health — table-overflow tally (#91 slice 3)");
    RUN_TEST(test_tally_starts_at_zero);
    RUN_TEST(test_tally_counts_per_kind);
    RUN_TEST(test_tally_is_monotonic);
    RUN_TEST(test_tally_ignores_out_of_range_kinds);
    RUN_TEST(test_evict_names_are_stable_and_distinct);
    RUN_TEST(test_schema_doc_lists_every_counted_table);

    TEST_SUITE("sensor health — eviction sites reach the tally (#91 slice 3)");
    RUN_TEST(test_pnl_ssid_overflow_is_counted);
    RUN_TEST(test_pnl_client_overflow_is_counted);
    RUN_TEST(test_top_host_overflow_is_counted);
    RUN_TEST(test_device_table_refusal_is_counted);
    RUN_TEST(test_beacon_table_overflow_is_counted);
    RUN_TEST(test_seqnum_table_overflow_is_counted);
    RUN_TEST(test_assoc_tables_overflow_is_counted);
    RUN_TEST(test_assoc_request_table_overflow_is_counted);
    RUN_TEST(test_alert_overflow_is_counted);

    TEST_SUITE("sensor health — per-protocol flow rings reach the tally (#91)");
    RUN_TEST(test_flow_ring_fill_to_cap_is_not_a_loss);
    RUN_TEST(test_flow_ring_overwrite_is_counted);
    RUN_TEST(test_flow_ring_clear_restores_empty_occupancy);
    RUN_TEST(test_flow_ring_snapshot_still_caps_at_max);
    RUN_TEST(test_flow_rings_are_classified_apart_from_tables);
    RUN_TEST(test_table_subtotal_excludes_flow_rings);
    RUN_TEST(test_flow_ring_overflow_counted_through_the_parser);

    TEST_SUITE("sensor health — parse-fault tally (#126)");
    RUN_TEST(test_parse_fault_tally_counts_per_kind);
    RUN_TEST(test_parse_fault_ignores_out_of_range_kinds);
    RUN_TEST(test_parse_faults_do_not_reach_the_eviction_tally);
    RUN_TEST(test_parse_fault_names_are_stable_and_distinct);
    RUN_TEST(test_parse_fault_wired_set);
    RUN_TEST(test_schema_doc_lists_every_parse_fault_kind);
    RUN_TEST(test_beacon_ie_overrun_reaches_the_parse_fault_tally);
    RUN_TEST(test_beacon_clean_ies_add_no_parse_fault);
    RUN_TEST(test_beacon_one_byte_tail_is_tallied_not_scored);

    TEST_SUITE("sensor health — process memory sample (#121)");
    RUN_TEST(test_mem_parse_status_reads_rss_and_hwm);
    RUN_TEST(test_mem_parse_status_absent_is_unmeasured);
    RUN_TEST(test_mem_parse_status_rejects_non_numbers);
    RUN_TEST(test_mem_parse_status_stops_at_len);
    RUN_TEST(test_mem_sample_reads_this_process);
    RUN_TEST(test_mem_sample_counts_an_opened_fd);
    RUN_TEST(test_mem_sample_follows_sqlite_allocator);
    RUN_TEST(test_mem_sample_follows_glibc_malloc);
    RUN_TEST(test_mem_sample_reports_resolver_counter);
    RUN_TEST(test_schema_doc_lists_every_memory_field);

    sh_evict_reset();   /* leave the tally clean for later suites */
    sh_parse_fault_reset();
}
