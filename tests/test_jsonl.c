#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "jsonl.h"
#include "tls_log.h"
#include "dns_log.h"
#include "ntp_log.h"
#include "icmp_log.h"

/* Each test opens a fresh temp file, exercises the emitter, then reads
 * the file back and asserts on the recorded line(s). */

static char tmp_path[] = "/tmp/sloth_jsonl_XXXXXX";

static void open_fresh(void) {
    /* Build a unique path; close immediately so jsonl_open can append. */
    int fd = mkstemp(tmp_path);
    if (fd >= 0) close(fd);
    jsonl_close();
    /* truncate any previous content */
    FILE *fp = fopen(tmp_path, "w"); if (fp) fclose(fp);
    ASSERT(jsonl_open(tmp_path));
}

static char *slurp(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    static char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

static int contains(const char *hay, const char *needle) {
    return strstr(hay, needle) != NULL;
}

/* ── open / close ────────────────────────────────────────── */

static void test_open_close(void) {
    open_fresh();
    ASSERT(jsonl_is_open());
    jsonl_close();
    ASSERT(!jsonl_is_open());
}

static void test_emit_without_open_is_noop(void) {
    jsonl_close();
    dns_log_entry_t e; memset(&e, 0, sizeof(e));
    snprintf(e.src, sizeof(e.src), "1.2.3.4");
    snprintf(e.qname, sizeof(e.qname), "example.com");
    jsonl_emit_dns(&e);  /* must not crash */
    ASSERT(1);
}

static void test_open_invalid_path_fails(void) {
    jsonl_close();
    ASSERT(!jsonl_open("/this/should/not/exist/nopath/out.jsonl"));
    ASSERT(!jsonl_is_open());
}

/* ── per-type emit ───────────────────────────────────────── */

static void test_emit_dns_writes_fields(void) {
    open_fresh();
    dns_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000000;
    snprintf(e.src,    sizeof(e.src),    "192.168.1.5");
    snprintf(e.qname,  sizeof(e.qname),  "example.com");
    snprintf(e.qtype,  sizeof(e.qtype),  "A");
    snprintf(e.answer, sizeof(e.answer), "93.184.216.34");
    e.is_resp = 1;
    jsonl_emit_dns(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(body != NULL);
    ASSERT(contains(body, "\"type\":\"dns\""));
    ASSERT(contains(body, "\"src\":\"192.168.1.5\""));
    ASSERT(contains(body, "\"qname\":\"example.com\""));
    ASSERT(contains(body, "\"qtype\":\"A\""));
    ASSERT(contains(body, "\"answer\":\"93.184.216.34\""));
    ASSERT(contains(body, "\"ts\":1700000000"));
    ASSERT(contains(body, "\"is_resp\":1"));
}

static void test_emit_tls_writes_ja3(void) {
    open_fresh();
    tls_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000001;
    snprintf(e.src, sizeof(e.src), "10.0.0.5");
    snprintf(e.dst, sizeof(e.dst), "93.184.216.34");
    snprintf(e.host, sizeof(e.host), "example.com");
    snprintf(e.tls_ver, sizeof(e.tls_ver), "TLS 1.3");
    snprintf(e.ja3, sizeof(e.ja3), "deadbeefcafef00d00112233445566ff");
    jsonl_emit_tls(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(contains(body, "\"type\":\"tls\""));
    ASSERT(contains(body, "\"ja3\":\"deadbeefcafef00d00112233445566ff\""));
    ASSERT(contains(body, "\"host\":\"example.com\""));
    ASSERT(contains(body, "\"ver\":\"TLS 1.3\""));
}

static void test_emit_ntp_writes_numeric_fields(void) {
    open_fresh();
    ntp_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000002;
    e.version = 4; e.stratum = 1;
    snprintf(e.src,  sizeof(e.src),  "10.0.0.1");
    snprintf(e.dst,  sizeof(e.dst),  "192.168.1.5");
    snprintf(e.mode, sizeof(e.mode), "server");
    snprintf(e.ref,  sizeof(e.ref),  "GPS");
    jsonl_emit_ntp(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(contains(body, "\"type\":\"ntp\""));
    ASSERT(contains(body, "\"version\":4"));
    ASSERT(contains(body, "\"stratum\":1"));
    ASSERT(contains(body, "\"mode\":\"server\""));
    ASSERT(contains(body, "\"ref\":\"GPS\""));
}

static void test_emit_icmp_writes_seq(void) {
    open_fresh();
    icmp_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000003;
    e.type = 8; e.code = 0; e.seq = 42; e.is_v6 = 0;
    snprintf(e.src, sizeof(e.src), "192.168.1.5");
    snprintf(e.dst, sizeof(e.dst), "8.8.8.8");
    snprintf(e.desc, sizeof(e.desc), "Echo Req");
    jsonl_emit_icmp(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(contains(body, "\"type\":\"icmp\""));
    ASSERT(contains(body, "\"seq\":42"));
    ASSERT(contains(body, "\"desc\":\"Echo Req\""));
    ASSERT(contains(body, "\"v6\":0"));
}

/* Kills the `is_v6 ? 1 : 0` const-1 mutation in jsonl_emit_icmp:
 * with is_v6=1 set, the JSON must emit `"v6":1`, not `"v6":2`. */
static void test_emit_icmp_v6_true_writes_one(void) {
    open_fresh();
    icmp_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000003;
    e.type = 129; e.code = 0; e.seq = 7; e.is_v6 = 1;
    snprintf(e.src, sizeof(e.src), "2001:db8::1");
    snprintf(e.dst, sizeof(e.dst), "2001:db8::2");
    snprintf(e.desc, sizeof(e.desc), "Echo Reply v6");
    jsonl_emit_icmp(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(contains(body, "\"v6\":1"));
    /* Mutation 1->2 would render "v6":2; explicitly assert that
     * pattern does NOT appear, so the test fails on the mutation. */
    ASSERT(!contains(body, "\"v6\":2"));
}

/* Connections snapshot: mixes TCP (with state/rtt/retx) and UDP (without)
 * in one state, asserts both record shapes appear.
 *
 * Touches conn_rebuild_idx so bw_lookup can find a bw entry — we don't
 * pre-populate s->conn_bw here, so rx_bytes/tx_bytes fall back to 0,
 * which is the documented behaviour when WITH_PCAP=0. */
static void test_emit_connections_tcp_and_udp(void) {
    open_fresh();
    sloth_state_t s; memset(&s, 0, sizeof(s));

    snprintf(s.conns[0].local_addr,  sizeof(s.conns[0].local_addr),  "10.0.0.5");
    snprintf(s.conns[0].remote_addr, sizeof(s.conns[0].remote_addr), "93.184.216.34");
    s.conns[0].local_port  = 49152;
    s.conns[0].remote_port = 443;
    s.conns[0].proto       = PROTO_TCP;
    s.conns[0].state       = 1;       /* ESTABLISHED */
    s.conns[0].rtt_us      = 12400;   /* → 12.4 ms */
    s.conns[0].retrans     = 3;

    snprintf(s.conns[1].local_addr,  sizeof(s.conns[1].local_addr),  "10.0.0.5");
    snprintf(s.conns[1].remote_addr, sizeof(s.conns[1].remote_addr), "1.1.1.1");
    s.conns[1].local_port  = 53000;
    s.conns[1].remote_port = 53;
    s.conns[1].proto       = PROTO_UDP;

    s.conn_count = 2;

    jsonl_emit_connections(&s);
    jsonl_close();

    char *body = slurp(tmp_path);
    ASSERT(body != NULL);
    /* TCP record: has state/rtt_ms/retx */
    ASSERT(contains(body, "\"type\":\"connections\""));
    ASSERT(contains(body, "\"src\":\"10.0.0.5:49152\""));
    ASSERT(contains(body, "\"dst\":\"93.184.216.34:443\""));
    ASSERT(contains(body, "\"proto\":\"tcp\""));
    ASSERT(contains(body, "\"state\":\"ESTABLISHED\""));
    ASSERT(contains(body, "\"rtt_ms\":12.4"));
    ASSERT(contains(body, "\"retx\":3"));
    /* UDP record: no state/rtt_ms/retx */
    ASSERT(contains(body, "\"src\":\"10.0.0.5:53000\""));
    ASSERT(contains(body, "\"dst\":\"1.1.1.1:53\""));
    ASSERT(contains(body, "\"proto\":\"udp\""));
    /* rx_bytes/tx_bytes always present, zero when no bw entry */
    ASSERT(contains(body, "\"rx_bytes\":0"));
    ASSERT(contains(body, "\"tx_bytes\":0"));
}

/* IPv6 endpoints render bracketed: [addr]:port. */
static void test_emit_connections_v6_brackets_address(void) {
    open_fresh();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snprintf(s.conns[0].local_addr,  sizeof(s.conns[0].local_addr),  "fe80::1");
    snprintf(s.conns[0].remote_addr, sizeof(s.conns[0].remote_addr), "2606:4700:4700::1111");
    s.conns[0].local_port  = 54321;
    s.conns[0].remote_port = 443;
    s.conns[0].proto       = PROTO_TCP;
    s.conns[0].state       = 1;
    s.conn_count = 1;

    jsonl_emit_connections(&s);
    jsonl_close();

    char *body = slurp(tmp_path);
    ASSERT(body != NULL);
    ASSERT(contains(body, "\"src\":\"[fe80::1]:54321\""));
    ASSERT(contains(body, "\"dst\":\"[2606:4700:4700::1111]:443\""));
}

/* Twin episode emitter — exercise all flag fields and the BSSID
 * lowercasing/colon formatting. */
static void test_emit_twin_episode_full_fields(void) {
    open_fresh();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    twin_episode_t *e = &s.twin_episodes[s.twin_episode_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->ssid, sizeof(e->ssid), "Cafe-Net");
    uint8_t real[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t twin[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    memcpy(e->real_bssid, real, 6);
    memcpy(e->twin_bssid, twin, 6);
    snprintf(e->enc, sizeof(e->enc), "WPA2");
    e->real_rssi          = -70;
    e->twin_rssi          = -45;
    e->rssi_swing_dbm     = 25;
    e->attack_in_progress = 1;
    e->attacker_oui       = 1;
    e->hash_mismatch      = 1;
    e->last_seen          = 1700000000;

    jsonl_emit_twin_episodes(&s);
    jsonl_close();

    char *body = slurp(tmp_path);
    ASSERT(body != NULL);
    ASSERT(contains(body, "\"type\":\"twin_episode\""));
    ASSERT(contains(body, "\"ssid\":\"Cafe-Net\""));
    ASSERT(contains(body, "\"real_bssid\":\"aa:bb:cc:01:02:03\""));
    ASSERT(contains(body, "\"twin_bssid\":\"11:22:33:44:55:66\""));
    ASSERT(contains(body, "\"enc\":\"WPA2\""));
    ASSERT(contains(body, "\"real_rssi\":-70"));
    ASSERT(contains(body, "\"twin_rssi\":-45"));
    ASSERT(contains(body, "\"rssi_swing_dbm\":25"));
    ASSERT(contains(body, "\"attack_in_progress\":1"));
    ASSERT(contains(body, "\"attacker_oui\":1"));
    ASSERT(contains(body, "\"hash_mismatch\":1"));
}

/* No episodes → no output. */
static void test_emit_twin_episode_empty_no_output(void) {
    open_fresh();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    jsonl_emit_twin_episodes(&s);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(body != NULL);
    ASSERT(!contains(body, "twin_episode"));
}

/* TCP entry with rtt_us == 0 should omit rtt_ms entirely (not emit "0.0"). */
static void test_emit_connections_omits_zero_rtt(void) {
    open_fresh();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snprintf(s.conns[0].local_addr,  sizeof(s.conns[0].local_addr),  "10.0.0.5");
    snprintf(s.conns[0].remote_addr, sizeof(s.conns[0].remote_addr), "10.0.0.1");
    s.conns[0].local_port  = 22;
    s.conns[0].remote_port = 33333;
    s.conns[0].proto       = PROTO_TCP;
    s.conns[0].state       = 1;
    s.conns[0].rtt_us      = 0;
    s.conn_count = 1;

    jsonl_emit_connections(&s);
    jsonl_close();

    char *body = slurp(tmp_path);
    ASSERT(body != NULL);
    ASSERT(!contains(body, "rtt_ms"));
}

static void test_emit_alert_writes_count(void) {
    open_fresh();
    alert_t a; memset(&a, 0, sizeof(a));
    a.last_seen = 1700000004;
    a.sev = ALERT_SEV_CRIT;
    a.type = ALERT_TYPE_THREAT_DOMAIN;
    a.count = 7;
    snprintf(a.title,  sizeof(a.title),  "THREAT_DOMAIN");
    snprintf(a.detail, sizeof(a.detail), "saw malware.testing.com");
    snprintf(a.key,    sizeof(a.key),    "threat-d:malware.testing.com");
    jsonl_emit_alert(&a);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(contains(body, "\"type\":\"alert\""));
    ASSERT(contains(body, "\"title\":\"THREAT_DOMAIN\""));
    ASSERT(contains(body, "\"count\":7"));
    ASSERT(contains(body, "\"detail\":\"saw malware.testing.com\""));
}

/* ── escaping ────────────────────────────────────────────── */

static void test_json_escapes_quotes_and_backslash(void) {
    open_fresh();
    dns_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000005;
    snprintf(e.qname, sizeof(e.qname), "weird \"\\\\name");
    jsonl_emit_dns(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    /* Resulting JSON should contain \" and \\ escapes. */
    ASSERT(contains(body, "\\\""));
    ASSERT(contains(body, "\\\\"));
}

static void test_json_escapes_newline_in_field(void) {
    open_fresh();
    dns_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000006;
    snprintf(e.qname, sizeof(e.qname), "ab\ncd");
    jsonl_emit_dns(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(contains(body, "\\n"));
}

/* Aggregate state-snapshot emitter — drives one entry into every
 * table the iOS client needs and asserts every record type lands.
 * Single test rather than 21 individual ones because the emitter
 * bodies are mechanical; this gives broad coverage with a single
 * point of failure when the umbrella is wired up. */
static void test_emit_state_snapshots_covers_all_view_types(void) {
    open_fresh();
    sloth_state_t s; memset(&s, 0, sizeof(s));

    /* iface */
    snprintf(s.ifaces[0].name, sizeof(s.ifaces[0].name), "eth0");
    s.ifaces[0].rx_bytes = 12345; s.ifaces[0].mtu = 1500;
    s.iface_count = 1;

    /* arp */
    snprintf(s.arp_entries[0].ip, sizeof(s.arp_entries[0].ip), "10.0.0.1");
    snprintf(s.arp_entries[0].iface, sizeof(s.arp_entries[0].iface), "eth0");
    s.arp_entries[0].mac[0] = 0xaa;
    s.arp_count = 1;

    /* dhcp_lease */
    snprintf(s.dhcp_leases[0].ip, sizeof(s.dhcp_leases[0].ip), "10.0.0.50");
    snprintf(s.dhcp_leases[0].hostname, sizeof(s.dhcp_leases[0].hostname), "laptop");
    s.dhcp_count = 1;

    /* wifi_ap (simple) */
    snprintf(s.aps[0].ssid,  sizeof(s.aps[0].ssid),  "Home");
    snprintf(s.aps[0].bssid, sizeof(s.aps[0].bssid), "aa:bb:cc:dd:ee:ff");
    s.ap_count = 1;

    /* wifi_sta */
    snprintf(s.wifi_stas[0].mac, sizeof(s.wifi_stas[0].mac), "11:22:33:44:55:66");
    s.wifi_sta_count = 1;

    /* top_host */
    snprintf(s.top_hosts[0].ip,       sizeof(s.top_hosts[0].ip),       "1.1.1.1");
    snprintf(s.top_hosts[0].hostname, sizeof(s.top_hosts[0].hostname), "one.one.one.one");
    s.top_host_count = 1;

    /* device */
    s.devices[0].mac[0] = 0xde;
    snprintf(s.devices[0].vendor, sizeof(s.devices[0].vendor), "Apple");
    s.device_count = 1;

    /* beacon */
    snprintf(s.beacon_aps[0].ssid, sizeof(s.beacon_aps[0].ssid), "Cafe");
    snprintf(s.beacon_aps[0].enc,  sizeof(s.beacon_aps[0].enc),  "WPA2");
    s.beacon_aps[0].bssid[0] = 0xab;
    s.beacon_count = 1;

    /* deauth */
    s.deauth_events[0].bssid[0] = 0xcc;
    s.deauth_events[0].flood = 1;
    s.deauth_count = 1;

    /* probe_client */
    snprintf(s.probe_clients[0].ssid, sizeof(s.probe_clients[0].ssid), "MyNet");
    s.probe_count = 1;

    /* pnl_client */
    snprintf(s.pnl_clients[0].ssids[0], sizeof(s.pnl_clients[0].ssids[0]), "MyNet");
    s.pnl_clients[0].ssid_count = 1;
    s.pnl_count = 1;

    /* seqnum_client */
    s.seqnum_clients[0].mac[0] = 0xde;
    s.seqnum_clients[0].hist[0] = 0x123;
    s.seqnum_clients[0].hist_n = 1;
    s.seqnum_count = 1;

    /* seqnum_correlation */
    s.seqnum_correlations[0].mac_a[0] = 0xaa;
    s.seqnum_correlations[0].mac_b[0] = 0xbb;
    s.seqnum_correlations[0].gap      = 3;
    s.seqnum_correlation_count = 1;

    /* channel_summary */
    s.channels[0].channel  = 36;
    s.channels[0].ap_count = 4;
    s.channel_count = 1;

    /* assoc */
    s.assocs[0].bssid[0] = 0xa1;
    snprintf(s.assocs[0].ssid, sizeof(s.assocs[0].ssid), "Office");
    s.assoc_count = 1;

    /* eapol */
    s.eapol_events[0].bssid[0] = 0xe1;
    s.eapol_events[0].has_pmkid = 1;
    s.eapol_count = 1;

    /* mdns_service */
    snprintf(s.mdns_services[0].service,  sizeof(s.mdns_services[0].service),  "_ipp._tcp");
    snprintf(s.mdns_services[0].instance, sizeof(s.mdns_services[0].instance), "Printer");
    s.mdns_count = 1;

    /* nbns_name */
    snprintf(s.nbns_names[0].name, sizeof(s.nbns_names[0].name), "DESKTOP");
    s.nbns_count = 1;

    /* ssdp_device */
    snprintf(s.ssdp_devices[0].usn,  sizeof(s.ssdp_devices[0].usn),  "uuid:xyz");
    snprintf(s.ssdp_devices[0].type, sizeof(s.ssdp_devices[0].type), "urn:roku");
    s.ssdp_count = 1;

    /* scan_entry */
    snprintf(s.scan_entries[0].ip, sizeof(s.scan_entries[0].ip), "10.0.0.99");
    s.scan_entries[0].port_count = 3;
    s.scan_entries[0].ports[0]   = 22;
    s.scan_count = 1;

    /* packet */
    s.packets[0].ts_sec = 1700000000;
    snprintf(s.packets[0].src, sizeof(s.packets[0].src), "10.0.0.5");
    snprintf(s.packets[0].dst, sizeof(s.packets[0].dst), "8.8.8.8");
    s.pkt_count = 1;

    /* process — driven by procs_aggregate over s->conns. Seed one
     * conn with a non-zero pid so the aggregator produces a row. */
    snprintf(s.conns[0].local_addr,  sizeof(s.conns[0].local_addr),  "10.0.0.5");
    snprintf(s.conns[0].remote_addr, sizeof(s.conns[0].remote_addr), "1.1.1.1");
    s.conns[0].local_port  = 50000;
    s.conns[0].remote_port = 443;
    s.conns[0].proto       = PROTO_TCP;
    s.conns[0].pid         = 1234;
    snprintf(s.conns[0].proc, sizeof(s.conns[0].proc), "firefox");
    s.conn_count = 1;

    jsonl_emit_state_snapshots(&s);
    jsonl_close();

    char *body = slurp(tmp_path);
    ASSERT(body != NULL);
    /* Every record type must appear at least once. */
    ASSERT(contains(body, "\"type\":\"iface\""));
    ASSERT(contains(body, "\"name\":\"eth0\""));
    ASSERT(contains(body, "\"type\":\"arp\""));
    ASSERT(contains(body, "\"iface\":\"eth0\""));
    ASSERT(contains(body, "\"type\":\"dhcp_lease\""));
    ASSERT(contains(body, "\"hostname\":\"laptop\""));
    ASSERT(contains(body, "\"type\":\"wifi_ap\""));
    ASSERT(contains(body, "\"ssid\":\"Home\""));
    ASSERT(contains(body, "\"type\":\"wifi_sta\""));
    ASSERT(contains(body, "\"type\":\"top_host\""));
    ASSERT(contains(body, "\"hostname\":\"one.one.one.one\""));
    ASSERT(contains(body, "\"type\":\"device\""));
    ASSERT(contains(body, "\"vendor\":\"Apple\""));
    ASSERT(contains(body, "\"type\":\"beacon\""));
    ASSERT(contains(body, "\"ssid\":\"Cafe\""));
    ASSERT(contains(body, "\"type\":\"deauth\""));
    ASSERT(contains(body, "\"flood\":1"));
    ASSERT(contains(body, "\"type\":\"probe_client\""));
    ASSERT(contains(body, "\"type\":\"pnl_client\""));
    ASSERT(contains(body, "\"ssids\":[\"MyNet\"]"));
    ASSERT(contains(body, "\"type\":\"seqnum_client\""));
    ASSERT(contains(body, "\"hist\":[291]"));   /* 0x123 == 291 */
    ASSERT(contains(body, "\"type\":\"seqnum_correlation\""));
    ASSERT(contains(body, "\"gap\":3"));
    ASSERT(contains(body, "\"type\":\"channel_summary\""));
    ASSERT(contains(body, "\"channel\":36"));
    ASSERT(contains(body, "\"type\":\"assoc\""));
    ASSERT(contains(body, "\"ssid\":\"Office\""));
    ASSERT(contains(body, "\"type\":\"eapol\""));
    ASSERT(contains(body, "\"has_pmkid\":1"));
    ASSERT(contains(body, "\"type\":\"mdns_service\""));
    ASSERT(contains(body, "\"service\":\"_ipp._tcp\""));
    ASSERT(contains(body, "\"type\":\"nbns_name\""));
    ASSERT(contains(body, "\"name\":\"DESKTOP\""));
    ASSERT(contains(body, "\"type\":\"ssdp_device\""));
    ASSERT(contains(body, "\"usn\":\"uuid:xyz\""));
    ASSERT(contains(body, "\"type\":\"scan_entry\""));
    ASSERT(contains(body, "\"ports\":[22"));
    ASSERT(contains(body, "\"type\":\"packet\""));
    ASSERT(contains(body, "\"src\":\"10.0.0.5\""));
    ASSERT(contains(body, "\"type\":\"process\""));
    ASSERT(contains(body, "\"proc\":\"firefox\""));
    ASSERT(contains(body, "\"pid\":1234"));
}

/* Empty state → no snapshot records emitted (every table count = 0). */
static void test_emit_state_snapshots_empty_writes_nothing(void) {
    open_fresh();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    jsonl_emit_state_snapshots(&s);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(body != NULL);
    /* Sanity: no record types from the umbrella appear. */
    ASSERT(!contains(body, "\"type\":\"iface\""));
    ASSERT(!contains(body, "\"type\":\"beacon\""));
    ASSERT(!contains(body, "\"type\":\"device\""));
}

/* ── per-record() integration (a parallel write through the log API) ── */

static void test_dns_log_record_writes_jsonl(void) {
    open_fresh();
    dns_log_clear();

    dns_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000007;
    snprintf(e.src,    sizeof(e.src),    "10.0.0.10");
    snprintf(e.qname,  sizeof(e.qname),  "tracker.example.com");
    snprintf(e.qtype,  sizeof(e.qtype),  "A");
    dns_log_record(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(contains(body, "\"qname\":\"tracker.example.com\""));
}

/* ── Suite ───────────────────────────────────────────────── */

void run_jsonl_tests(void) {
    TEST_SUITE("jsonl open/close");
    RUN_TEST(test_open_close);
    RUN_TEST(test_emit_without_open_is_noop);
    RUN_TEST(test_open_invalid_path_fails);

    TEST_SUITE("jsonl emit");
    RUN_TEST(test_emit_dns_writes_fields);
    RUN_TEST(test_emit_tls_writes_ja3);
    RUN_TEST(test_emit_ntp_writes_numeric_fields);
    RUN_TEST(test_emit_icmp_writes_seq);
    RUN_TEST(test_emit_icmp_v6_true_writes_one);
    RUN_TEST(test_emit_alert_writes_count);
    RUN_TEST(test_emit_connections_tcp_and_udp);
    RUN_TEST(test_emit_connections_v6_brackets_address);
    RUN_TEST(test_emit_connections_omits_zero_rtt);
    RUN_TEST(test_emit_twin_episode_full_fields);
    RUN_TEST(test_emit_twin_episode_empty_no_output);
    RUN_TEST(test_emit_state_snapshots_covers_all_view_types);
    RUN_TEST(test_emit_state_snapshots_empty_writes_nothing);

    TEST_SUITE("jsonl escaping");
    RUN_TEST(test_json_escapes_quotes_and_backslash);
    RUN_TEST(test_json_escapes_newline_in_field);

    TEST_SUITE("jsonl record-hook");
    RUN_TEST(test_dns_log_record_writes_jsonl);
}
