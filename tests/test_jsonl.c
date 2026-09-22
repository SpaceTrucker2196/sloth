#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/resource.h>
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
    /* Drop any previous content. jsonl_open recreates the file 0600; a
     * fopen("w") here would recreate it umask-dependent and have it
     * refused (#87). */
    unlink(tmp_path);
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

/* Beacon record carries the IE-ordering fingerprint (#77) — additive
 * fields beside vendor_ies_hash. 0xb6770ade == 3061254878. */
static void test_emit_beacon_ie_order_fields(void) {
    open_fresh();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_ap_t *b = &s.beacon_aps[s.beacon_count++];
    snprintf(b->ssid, sizeof(b->ssid), "Lab");
    b->fp.ie_order_hash  = 0xb6770adeu;
    b->fp.ie_order_count = 8;

    jsonl_emit_beacons(&s);
    jsonl_close();

    char *body = slurp(tmp_path);
    ASSERT(body != NULL);
    ASSERT(contains(body, "\"type\":\"beacon\""));
    ASSERT(contains(body, "\"ie_order_hash\":3061254878"));
    ASSERT(contains(body, "\"ie_order_count\":8"));
}

/* Beacon record carries the TBTT-jitter observable (#77) — the derived
 * stddev in µs plus the sample and reset counts, so a consumer can tell
 * "no jitter" from "not enough beacons to say". Accumulator: 2 samples
 * of ±1500 µs about a zero mean -> stddev 1500. */
static void test_emit_beacon_tbtt_jitter_fields(void) {
    open_fresh();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_ap_t *b = &s.beacon_aps[s.beacon_count++];
    snprintf(b->ssid, sizeof(b->ssid), "Lab");
    b->tbtt.samples  = 2;
    b->tbtt.sum_us   = 0;
    b->tbtt.sumsq_us = 2ull * 1500ull * 1500ull;
    b->tbtt.resets   = 3;

    jsonl_emit_beacons(&s);
    jsonl_close();

    char *body = slurp(tmp_path);
    ASSERT(body != NULL);
    ASSERT(contains(body, "\"tbtt_jitter_us\":1500"));
    ASSERT(contains(body, "\"tbtt_jitter_samples\":2"));
    ASSERT(contains(body, "\"tbtt_jitter_resets\":3"));
}

/* A BSSID heard once has a baseline but no residual. The stddev field
 * must read 0 with a sample count of 0 beside it — the pair is what
 * keeps 0 from being read as "this AP is perfectly scheduled". */
static void test_emit_beacon_tbtt_jitter_absent_is_zero(void) {
    open_fresh();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_ap_t *b = &s.beacon_aps[s.beacon_count++];
    snprintf(b->ssid, sizeof(b->ssid), "Lab");
    b->tbtt.have_last = 1;
    b->tbtt.last_tsf  = 12345678ull;

    jsonl_emit_beacons(&s);
    jsonl_close();

    char *body = slurp(tmp_path);
    ASSERT(body != NULL);
    ASSERT(contains(body, "\"tbtt_jitter_us\":0"));
    ASSERT(contains(body, "\"tbtt_jitter_samples\":0"));
}

/* Hostile-AP worst case: every attacker-controlled string field filled
 * to capacity with a byte json_escape expands 6x (\u0001). The record
 * used to overrun LINEBUF — snprintf's would-be length pushed `off`
 * past the buffer, (size_t)(LINEBUF - off) wrapped, and the next write
 * landed out of bounds. It must now come out whole: the closing "]}"
 * of neighbors[] proves nothing was truncated. */
static void fill_ctl(char *dst, size_t sz) {
    memset(dst, 0x01, sz - 1);
    dst[sz - 1] = '\0';
}

/* slurp() caps at 4 KiB; worst-case records are larger. */
static const char *slurp_big(const char *path, size_t *n_out) {
    static char body[32768];
    FILE *fp = fopen(path, "r");
    size_t n = fp ? fread(body, 1, sizeof(body) - 1, fp) : 0;
    if (fp) fclose(fp);
    body[n] = '\0';
    ASSERT(n > 0 && n < sizeof(body) - 1);
    *n_out = n;
    return body;
}

static void test_emit_beacon_worst_case_escaping_fits(void) {
    open_fresh();
    static sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_ap_t *b = &s.beacon_aps[s.beacon_count++];
    fill_ctl(b->ssid, sizeof(b->ssid));
    fill_ctl(b->enc, sizeof(b->enc));
    fill_ctl(b->pairwise, sizeof(b->pairwise));
    fill_ctl(b->group, sizeof(b->group));
    fill_ctl(b->akm, sizeof(b->akm));
    fill_ctl(b->vendor, sizeof(b->vendor));
    fill_ctl(b->wps_manufacturer, sizeof(b->wps_manufacturer));
    fill_ctl(b->wps_model_name, sizeof(b->wps_model_name));
    fill_ctl(b->wps_model_number, sizeof(b->wps_model_number));
    fill_ctl(b->wps_serial, sizeof(b->wps_serial));
    fill_ctl(b->phy, sizeof(b->phy));
    for (int k = 0; k < MAX_AP_SSID_HISTORY; k++)
        fill_ctl(b->ssid_history[k], sizeof(b->ssid_history[k]));
    b->ssid_history_n = MAX_AP_SSID_HISTORY;
    b->has_qbss = 1;
    b->fuzz_ie_overruns = 1;
    for (int k = 0; k < MAX_AP_NEIGHBORS; k++) {
        memset(b->neighbors[k].bssid, 0xff, 6);
        b->neighbors[k].channel  = -2147483647 - 1;
        b->neighbors[k].phy_type = -2147483647 - 1;
    }
    b->neighbor_count = MAX_AP_NEIGHBORS;

    jsonl_emit_beacons(&s);
    jsonl_close();

    size_t n = 0;
    const char *body = slurp_big(tmp_path, &n);
    ASSERT(contains(body, "\"type\":\"beacon\""));
    ASSERT(contains(body, "\"wps_serial\":\"\\u0001"));
    ASSERT(n >= 3 && strcmp(body + n - 3, "]}\n") == 0);
}

/* Same exposure on the PNL record: any client's probe requests fill
 * ssids[] with up to MAX_PNL_SSIDS_PER_CLI attacker-chosen SSIDs. */
static void test_emit_pnl_worst_case_escaping_fits(void) {
    open_fresh();
    static sloth_state_t s; memset(&s, 0, sizeof(s));
    pnl_client_t *c = &s.pnl_clients[s.pnl_count++];
    c->mac[0] = 0x02;
    fill_ctl(c->os_fp, sizeof(c->os_fp));
    fill_ctl(c->phy, sizeof(c->phy));
    for (int k = 0; k < MAX_PNL_SSIDS_PER_CLI; k++)
        fill_ctl(c->ssids[k], sizeof(c->ssids[k]));
    c->ssid_count = MAX_PNL_SSIDS_PER_CLI;

    jsonl_emit_pnl_clients(&s);
    jsonl_close();

    size_t n = 0;
    const char *body = slurp_big(tmp_path, &n);
    ASSERT(contains(body, "\"type\":\"pnl_client\""));
    ASSERT(n >= 3 && strcmp(body + n - 3, "]}\n") == 0);
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
    s.pkt_count = 1; s.pkt_head = 1; s.pkt_total = 1;  /* mirror the capture write path */

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

/* ── packet once-only emission (issue #20 regression) ─────── */

static void push_pkt(sloth_state_t *s, const char *src) {
    /* Mirror the capture write path so the emitter sees a realistic ring. */
    packet_info_t p; memset(&p, 0, sizeof(p));
    p.ts_sec = 1700000000; p.proto = 6; p.len = 64;
    snprintf(p.src, sizeof(p.src), "%s", src);
    snprintf(p.dst, sizeof(p.dst), "8.8.8.8");
    s->packets[s->pkt_head] = p;
    s->pkt_head = (s->pkt_head + 1) % MAX_PACKETS;
    if (s->pkt_count < MAX_PACKETS) s->pkt_count++;
    s->pkt_total++;
}

static int line_count(const char *b) {
    int n = 0;
    for (; b && *b; b++) if (*b == '\n') n++;
    return n;
}

static void test_emit_packets_once_only(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    push_pkt(&s, "10.0.0.1");
    push_pkt(&s, "10.0.0.2");
    push_pkt(&s, "10.0.0.3");

    /* first emit ships all three new records */
    open_fresh();
    jsonl_emit_packets(&s);
    jsonl_close();
    ASSERT(line_count(slurp(tmp_path)) == 3);

    /* re-emitting with nothing new must ship zero — the whole point of #20 */
    open_fresh();
    jsonl_emit_packets(&s);
    jsonl_close();
    ASSERT(line_count(slurp(tmp_path)) == 0);

    /* two more arrive → only the two new records ship, not all five */
    push_pkt(&s, "10.0.0.4");
    push_pkt(&s, "10.0.0.5");
    open_fresh();
    jsonl_emit_packets(&s);
    jsonl_close();
    ASSERT(line_count(slurp(tmp_path)) == 2);
}

/* ── change-only snapshot emission (issue #42) ───────────────── */

static void seed_one_pnl(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
    s->pnl_clients[0].mac[0] = 0x02;   /* identity for the dedup key */
    s->pnl_clients[0].mac[5] = 0x11;
    snprintf(s->pnl_clients[0].ssids[0], sizeof(s->pnl_clients[0].ssids[0]), "HomeNet");
    s->pnl_clients[0].ssid_count  = 1;
    s->pnl_clients[0].probe_count = 3;
    s->pnl_clients[0].last_seen   = 1700000000;
    s->pnl_count = 1;
}

/* An unchanged row emitted twice in a row ships exactly once. */
static void test_dedup_suppresses_unchanged_pnl(void) {
    sloth_state_t s; seed_one_pnl(&s);
    open_fresh();                    /* jsonl_open resets the change cache */
    jsonl_emit_pnl_clients(&s);
    jsonl_emit_pnl_clients(&s);      /* nothing changed → suppressed */
    jsonl_close();
    ASSERT(line_count(slurp(tmp_path)) == 1);
}

/* A changed observation field re-emits the row. */
static void test_dedup_emits_on_change_pnl(void) {
    sloth_state_t s; seed_one_pnl(&s);
    open_fresh();
    jsonl_emit_pnl_clients(&s);
    s.pnl_clients[0].probe_count = 4;   /* novel observation */
    jsonl_emit_pnl_clients(&s);
    jsonl_close();
    ASSERT(line_count(slurp(tmp_path)) == 2);
}

/* A new SSID appended to the PNL is a change and re-emits. */
static void test_dedup_emits_on_new_ssid_pnl(void) {
    sloth_state_t s; seed_one_pnl(&s);
    open_fresh();
    jsonl_emit_pnl_clients(&s);
    snprintf(s.pnl_clients[0].ssids[1], sizeof(s.pnl_clients[0].ssids[1]), "Cafe");
    s.pnl_clients[0].ssid_count = 2;
    jsonl_emit_pnl_clients(&s);
    jsonl_close();
    ASSERT(line_count(slurp(tmp_path)) == 2);
}

/* Two distinct MACs are tracked independently — one changing doesn't
 * suppress or duplicate the other. */
static void test_dedup_distinct_macs_independent(void) {
    sloth_state_t s; seed_one_pnl(&s);
    s.pnl_clients[1] = s.pnl_clients[0];
    s.pnl_clients[1].mac[5] = 0x22;     /* different identity */
    s.pnl_count = 2;
    open_fresh();
    jsonl_emit_pnl_clients(&s);          /* both new → 2 lines */
    jsonl_emit_pnl_clients(&s);          /* both unchanged → 0 lines */
    jsonl_close();
    ASSERT(line_count(slurp(tmp_path)) == 2);
}

/* jsonl_dedup_reset forces a full baseline re-emit (the mechanism a fresh
 * sink / rotation relies on). */
static void test_dedup_reset_reemits_baseline(void) {
    sloth_state_t s; seed_one_pnl(&s);
    open_fresh();
    jsonl_emit_pnl_clients(&s);
    jsonl_dedup_reset();
    jsonl_emit_pnl_clients(&s);          /* unchanged, but cache cleared */
    jsonl_close();
    ASSERT(line_count(slurp(tmp_path)) == 2);
}

/* seqnum_client dedups on the same principle: identical frame_count/hist
 * suppresses, an advanced frame_count re-emits. */
static void test_dedup_seqnum_suppress_then_change(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.seqnum_clients[0].mac[0]      = 0xde;
    s.seqnum_clients[0].frame_count = 10;
    s.seqnum_clients[0].hist[0]     = 0x100;
    s.seqnum_clients[0].hist_n      = 1;
    s.seqnum_count = 1;

    open_fresh();
    jsonl_emit_seqnum_clients(&s);       /* new → 1 */
    jsonl_emit_seqnum_clients(&s);       /* unchanged → suppressed */
    s.seqnum_clients[0].frame_count = 11;
    s.seqnum_clients[0].hist[1]     = 0x105;
    s.seqnum_clients[0].hist_n      = 2;
    jsonl_emit_seqnum_clients(&s);       /* advanced → 1 more */
    jsonl_close();
    ASSERT(line_count(slurp(tmp_path)) == 2);
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


static void test_btm_steer_record(void) {
    open_fresh();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    btm_steer_t *b = &s.btm_steers[s.btm_steer_count++];
    static const uint8_t AP[6]  = {0xaa,0xbb,0xcc,0xdd,0xee,0x30};
    static const uint8_t STA[6] = {0x12,0x34,0x56,0x78,0x9a,0xbc};
    static const uint8_t CD[6]  = {0xaa,0xbb,0xcc,0xdd,0xee,0x31};
    memcpy(b->bssid, AP, 6);
    memcpy(b->sta,   STA, 6);
    memcpy(b->candidates[0], CD, 6);
    b->candidate_count      = 1;
    b->req_count            = 7;
    b->imminent_count       = 4;
    b->last_disassoc_timer  = 10;
    b->first_seen = b->last_seen = 1700000000;
    jsonl_emit_btm_steers(&s);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(body != NULL);
    ASSERT(strstr(body, "\"type\":\"btm_request\"") != NULL);
    ASSERT(strstr(body, "\"bssid\":\"aa:bb:cc:dd:ee:30\"") != NULL);
    ASSERT(strstr(body, "\"sta_mac\":\"12:34:56:78:9a:bc\"") != NULL);
    ASSERT(strstr(body, "\"req_count\":7") != NULL);
    /* The forcing subset is the field a consumer keys on — without it
     * an ordinary steering record and an attack look identical. */
    ASSERT(strstr(body, "\"imminent_count\":4") != NULL);
    ASSERT(strstr(body, "\"candidate_0\":\"aa:bb:cc:dd:ee:31\"") != NULL);
    unlink(tmp_path);
}

static void test_btm_steer_empty_emits_nothing(void) {
    open_fresh();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    jsonl_emit_btm_steers(&s);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(body != NULL);
    ASSERT(strstr(body, "btm_request") == NULL);
    unlink(tmp_path);
}

/* ── file permissions, #87 ───────────────────────────────── */

/* The JSONL stream carries cleartext-credential alerts, probe PNLs and
 * device MACs. Created private whatever the umask; an existing file
 * that is not private, or a symlink, is refused and left untouched. */

static void j87_path(char *out, size_t sz) {
    snprintf(out, sz, "/tmp/sloth_test_jsonl87_%d.jsonl", (int)getpid());
}

static int j87_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    return (int)(st.st_mode & 07777);
}

static long j87_size(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    return (long)st.st_size;
}

static void j87_emit(void) {
    dns_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000000;
    snprintf(e.src,   sizeof(e.src),   "192.168.1.5");
    snprintf(e.qname, sizeof(e.qname), "example.com");
    snprintf(e.qtype, sizeof(e.qtype), "A");
    jsonl_emit_dns(&e);
}

static void test_open_creates_private_under_permissive_umask(void) {
    char p[96]; j87_path(p, sizeof(p));
    unlink(p);
    jsonl_close();
    mode_t old = umask(022);
    ASSERT(jsonl_open(p));
    umask(old);
    ASSERT_EQ(j87_mode(p), 0600);
    jsonl_close();
    unlink(p);
}

static void test_open_refuses_permissive_existing_file(void) {
    char p[96]; j87_path(p, sizeof(p));
    unlink(p);
    jsonl_close();
    FILE *f = fopen(p, "w");
    if (f) { fputs("prior\n", f); fclose(f); }
    chmod(p, 0644);
    ASSERT(!jsonl_open(p));
    ASSERT(!jsonl_is_open());
    ASSERT(strstr(jsonl_error(), "0644") != NULL);
    ASSERT_EQ(j87_mode(p), 0644);                   /* not chmod'ed */
    ASSERT_EQ(j87_size(p), 6);                      /* not truncated */
    unlink(p);
}

static void test_open_refuses_symlink(void) {
    char p[96], victim[112];
    j87_path(p, sizeof(p));
    snprintf(victim, sizeof(victim), "%s.victim", p);
    unlink(p);
    jsonl_close();
    int fd = open(victim, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) close(fd);
    ASSERT_EQ(symlink(victim, p), 0);
    ASSERT(!jsonl_open(p));
    ASSERT(strstr(jsonl_error(), "symbolic link") != NULL);
    j87_emit();
    ASSERT_EQ(j87_size(victim), 0);
    unlink(p);
    unlink(victim);
}

/* A record that cannot be written is counted — RLIMIT_FSIZE stands in
 * for a full disk. */
static void test_write_failure_counted(void) {
    char p[96]; j87_path(p, sizeof(p));
    unlink(p);
    jsonl_close();
    ASSERT(jsonl_open(p));
    ASSERT_EQ(jsonl_write_failures(), 0);

    struct rlimit old, lim;
    getrlimit(RLIMIT_FSIZE, &old);
    lim = old;
    lim.rlim_cur = 8;
    void (*prev)(int) = signal(SIGXFSZ, SIG_IGN);
    setrlimit(RLIMIT_FSIZE, &lim);
    j87_emit();
    setrlimit(RLIMIT_FSIZE, &old);
    signal(SIGXFSZ, prev);

    ASSERT_GE(jsonl_write_failures(), 1);
    jsonl_close();
    unlink(p);
}

void run_jsonl_tests(void) {
    TEST_SUITE("jsonl open/close");
    RUN_TEST(test_open_close);
    RUN_TEST(test_emit_without_open_is_noop);
    RUN_TEST(test_open_invalid_path_fails);
    RUN_TEST(test_open_creates_private_under_permissive_umask);
    RUN_TEST(test_open_refuses_permissive_existing_file);
    RUN_TEST(test_open_refuses_symlink);
    RUN_TEST(test_write_failure_counted);

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
    RUN_TEST(test_emit_beacon_ie_order_fields);
    RUN_TEST(test_emit_beacon_tbtt_jitter_fields);
    RUN_TEST(test_emit_beacon_tbtt_jitter_absent_is_zero);
    RUN_TEST(test_emit_beacon_worst_case_escaping_fits);
    RUN_TEST(test_emit_pnl_worst_case_escaping_fits);
    RUN_TEST(test_emit_state_snapshots_covers_all_view_types);
    RUN_TEST(test_emit_state_snapshots_empty_writes_nothing);
    RUN_TEST(test_emit_packets_once_only);
    RUN_TEST(test_dedup_suppresses_unchanged_pnl);
    RUN_TEST(test_dedup_emits_on_change_pnl);
    RUN_TEST(test_dedup_emits_on_new_ssid_pnl);
    RUN_TEST(test_dedup_distinct_macs_independent);
    RUN_TEST(test_dedup_reset_reemits_baseline);
    RUN_TEST(test_dedup_seqnum_suppress_then_change);

    TEST_SUITE("jsonl escaping");
    RUN_TEST(test_json_escapes_quotes_and_backslash);
    RUN_TEST(test_json_escapes_newline_in_field);

    TEST_SUITE("jsonl record-hook");
    RUN_TEST(test_dns_log_record_writes_jsonl);
    RUN_TEST(test_btm_steer_record);
    RUN_TEST(test_btm_steer_empty_emits_nothing);
}
