#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "alert_pcap.h"

/* ── Helpers ─────────────────────────────────────────────── */

static char tmp_dir[] = "/tmp/sloth_pcap_XXXXXX";

static void ensure_tmp_dir(void) {
    /* mkdtemp creates the directory and writes the final name back. */
    char *d = mkdtemp(tmp_dir);
    (void)d;
    alert_pcap_set_dir(tmp_dir);
}

static void seed_packet(sloth_state_t *s,
                         const char *src, const char *dst,
                         uint16_t sport, uint16_t dport,
                         uint32_t ts_sec) {
    if (s->pkt_count >= MAX_PACKETS) return;
    int slot = s->pkt_head;
    packet_info_t *p = &s->packets[slot];
    memset(p, 0, sizeof(*p));
    snprintf(p->src, sizeof(p->src), "%s", src);
    snprintf(p->dst, sizeof(p->dst), "%s", dst);
    p->src_port = sport;
    p->dst_port = dport;
    p->ts_sec   = ts_sec;
    p->ts_usec  = 0;
    p->len      = 64;
    p->raw_len  = 32;
    for (int i = 0; i < 32; i++) p->raw[i] = (uint8_t)(i + 1);
    s->pkt_head = (s->pkt_head + 1) % MAX_PACKETS;
    if (s->pkt_count < MAX_PACKETS) s->pkt_count++;
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static long file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_size;
}

/* ── Tests ───────────────────────────────────────────────── */

static void test_set_dir_enables_disables(void) {
    alert_pcap_set_dir("/tmp");
    ASSERT(alert_pcap_enabled());
    alert_pcap_set_dir(NULL);
    ASSERT(!alert_pcap_enabled());
    alert_pcap_set_dir("");
    ASSERT(!alert_pcap_enabled());
}

static void test_dump_writes_pcap_for_match(void) {
    ensure_tmp_dir();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_packet(&s, "192.168.1.5", "203.0.113.7", 33445, 443, 1700000000);
    seed_packet(&s, "203.0.113.7", "192.168.1.5", 443,   33445, 1700000001);
    seed_packet(&s, "192.168.1.5", "8.8.8.8",     54321, 53,    1700000002);

    alert_t a; memset(&a, 0, sizeof(a));
    snprintf(a.title,    sizeof(a.title),    "THREAT_IP");
    snprintf(a.match_ip, sizeof(a.match_ip), "203.0.113.7");
    a.match_port = 443;
    char path[512];
    int n = alert_pcap_dump(&s, &a, path, sizeof(path));
    ASSERT_EQ(n, 2);
    ASSERT(file_exists(path));
    /* pcap global header is 24 bytes; each per-packet header is 16 +
       raw_len(32). Two packets → 24 + 2*(16+32) = 120 bytes. */
    ASSERT_EQ(file_size(path), 120);
}

static void test_dump_skips_when_no_match(void) {
    ensure_tmp_dir();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_packet(&s, "192.168.1.5", "8.8.8.8", 54321, 53, 1700000000);

    alert_t a; memset(&a, 0, sizeof(a));
    snprintf(a.title,    sizeof(a.title),    "THREAT_IP");
    snprintf(a.match_ip, sizeof(a.match_ip), "203.0.113.7");
    a.match_port = 443;

    char path[512] = "untouched";
    int n = alert_pcap_dump(&s, &a, path, sizeof(path));
    ASSERT_EQ(n, 0);
    /* path should still be "untouched" because no file was written */
    ASSERT_STR(path, "untouched");
}

static void test_dump_port_zero_matches_any(void) {
    ensure_tmp_dir();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_packet(&s, "10.0.0.99", "192.168.1.5", 11111, 22222, 1700000000);
    seed_packet(&s, "10.0.0.99", "192.168.1.5", 33333, 22222, 1700000001);

    alert_t a; memset(&a, 0, sizeof(a));
    snprintf(a.title,    sizeof(a.title),    "PORT_SCAN");
    snprintf(a.match_ip, sizeof(a.match_ip), "10.0.0.99");
    a.match_port = 0;  /* any port */

    char path[512];
    int n = alert_pcap_dump(&s, &a, path, sizeof(path));
    ASSERT_EQ(n, 2);
}

static void test_dump_noop_when_dir_disabled(void) {
    alert_pcap_set_dir(NULL);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_packet(&s, "192.168.1.5", "203.0.113.7", 33445, 443, 1700000000);

    alert_t a; memset(&a, 0, sizeof(a));
    snprintf(a.match_ip, sizeof(a.match_ip), "203.0.113.7");
    ASSERT_EQ(alert_pcap_dump(&s, &a, NULL, 0), 0);
}

static void test_dump_skips_alert_without_match_ip(void) {
    ensure_tmp_dir();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_packet(&s, "1.2.3.4", "5.6.7.8", 1, 2, 1700000000);

    alert_t a; memset(&a, 0, sizeof(a));
    snprintf(a.title, sizeof(a.title), "DEAUTH_FLOOD");
    /* match_ip empty */
    ASSERT_EQ(alert_pcap_dump(&s, &a, NULL, 0), 0);
}

/* ── Integration: rule fires populate match_ip ──────────── */

static void test_threat_ip_rule_sets_match_fields(void) {
    alert_pcap_set_dir(NULL);   /* keep pcap disabled — just check fields */
    alerts_clear();

    sloth_state_t s; memset(&s, 0, sizeof(s));
    conn_t *c = &s.conns[s.conn_count++];
    snprintf(c->local_addr,  sizeof(c->local_addr),  "192.168.1.5");
    snprintf(c->remote_addr, sizeof(c->remote_addr), "192.0.2.66");
    c->local_port  = 33445;
    c->remote_port = 443;
    c->proto       = PROTO_TCP;

    alerts_update(&s);
    int found = -1;
    for (int i = 0; i < s.alert_count; i++) {
        if (s.alerts[i].type == ALERT_TYPE_THREAT_IP) { found = i; break; }
    }
    ASSERT(found >= 0);
    ASSERT_STR(s.alerts[found].match_ip, "192.0.2.66");
    ASSERT_EQ((int)s.alerts[found].match_port, 443);
}

void run_alert_pcap_tests(void) {
    TEST_SUITE("alert_pcap dir gating");
    RUN_TEST(test_set_dir_enables_disables);

    TEST_SUITE("alert_pcap dump");
    RUN_TEST(test_dump_writes_pcap_for_match);
    RUN_TEST(test_dump_skips_when_no_match);
    RUN_TEST(test_dump_port_zero_matches_any);
    RUN_TEST(test_dump_noop_when_dir_disabled);
    RUN_TEST(test_dump_skips_alert_without_match_ip);

    TEST_SUITE("alert_pcap match-criteria integration");
    RUN_TEST(test_threat_ip_rule_sets_match_fields);
}
