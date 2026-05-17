#include <stdio.h>
#include <string.h>
#include <time.h>
#include "ntop.h"
#include "scan.h"
#include "views/conns.h"
#include "runner.h"

static void make_state(ntop_state_t *s) {
    memset(s, 0, sizeof(*s));
}

static void add_tcp_conn(ntop_state_t *s, const char *remote, uint16_t lport) {
    int i = s->conn_count++;
    s->conns[i].proto = PROTO_TCP;
    snprintf(s->conns[i].remote_addr, sizeof(s->conns[i].remote_addr), "%s", remote);
    s->conns[i].local_port  = lport;
    s->conns[i].remote_port = 443;
    snprintf(s->conns[i].local_addr, sizeof(s->conns[i].local_addr), "192.168.1.10");
}

static void test_below_threshold_not_flagged(void) {
    ntop_state_t s; make_state(&s);
    for (int p = 1024; p < 1031; p++)
        add_tcp_conn(&s, "1.2.3.4", (uint16_t)p);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "1.2.3.4") == 0);
}

static void test_at_threshold_flagged(void) {
    ntop_state_t s; make_state(&s);
    for (int p = 1024; p < 1032; p++)
        add_tcp_conn(&s, "1.2.3.4", (uint16_t)p);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "1.2.3.4") > 0);
}

static void test_above_threshold_flagged(void) {
    ntop_state_t s; make_state(&s);
    for (int p = 1024; p < 1040; p++)
        add_tcp_conn(&s, "5.6.7.8", (uint16_t)p);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "5.6.7.8") > 0);
}

static void test_private_ip_ignored(void) {
    ntop_state_t s; make_state(&s);
    for (int p = 1024; p < 1040; p++)
        add_tcp_conn(&s, "192.168.1.200", (uint16_t)p);
    scan_update(&s);
    ASSERT(s.scan_count == 0);
}

static void test_loopback_ignored(void) {
    ntop_state_t s; make_state(&s);
    for (int p = 1024; p < 1040; p++)
        add_tcp_conn(&s, "127.0.0.1", (uint16_t)p);
    scan_update(&s);
    ASSERT(s.scan_count == 0);
}

static void test_link_local_ignored(void) {
    ntop_state_t s; make_state(&s);
    for (int p = 1024; p < 1040; p++)
        add_tcp_conn(&s, "169.254.1.1", (uint16_t)p);
    scan_update(&s);
    ASSERT(s.scan_count == 0);
}

static void test_cgnat_ignored(void) {
    ntop_state_t s; make_state(&s);
    for (int p = 1024; p < 1040; p++)
        add_tcp_conn(&s, "100.100.1.1", (uint16_t)p);
    scan_update(&s);
    ASSERT(s.scan_count == 0);
}

static void test_port_dedup(void) {
    ntop_state_t s; make_state(&s);
    for (int i = 0; i < 20; i++)
        add_tcp_conn(&s, "8.8.8.8", 80);
    scan_update(&s);
    ASSERT(s.scan_count == 1);
    ASSERT(s.scan_entries[0].port_count == 1);
    ASSERT(scan_is_flagged(&s, "8.8.8.8") == 0);
}

static void test_flagged_returns_port_count(void) {
    ntop_state_t s; make_state(&s);
    for (int p = 1024; p < 1032; p++)
        add_tcp_conn(&s, "203.0.113.1", (uint16_t)p);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "203.0.113.1") >= 8);
}

static void test_unflagged_returns_zero(void) {
    ntop_state_t s; make_state(&s);
    add_tcp_conn(&s, "1.2.3.4", 80);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "1.2.3.4") == 0);
}

static void test_unknown_ip_returns_zero(void) {
    ntop_state_t s; make_state(&s);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "9.9.9.9") == 0);
}

static void test_ttl_expiry(void) {
    ntop_state_t s; make_state(&s);
    for (int p = 1024; p < 1032; p++)
        add_tcp_conn(&s, "4.4.4.4", (uint16_t)p);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "4.4.4.4") > 0);

    s.scan_entries[0].last_seen -= (SCAN_TTL_SECS + 10);
    s.conn_count = 0;
    scan_update(&s);
    ASSERT(s.scan_count == 0);
}

static void test_udp_not_tracked(void) {
    ntop_state_t s; make_state(&s);
    for (int p = 1024; p < 1040; p++) {
        int i = s.conn_count++;
        s.conns[i].proto = PROTO_UDP;
        snprintf(s.conns[i].remote_addr, 46, "1.2.3.4");
        s.conns[i].local_port = (uint16_t)p;
    }
    scan_update(&s);
    ASSERT(s.scan_count == 0);
}

static void test_multiple_ips_independent(void) {
    ntop_state_t s; make_state(&s);
    for (int p = 1024; p < 1032; p++) add_tcp_conn(&s, "203.0.113.10", (uint16_t)p);
    for (int p = 1024; p < 1028; p++) add_tcp_conn(&s, "203.0.113.20", (uint16_t)p);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "203.0.113.10") > 0);
    ASSERT(scan_is_flagged(&s, "203.0.113.20") == 0);
}

static void test_draw_no_scan(void) {
    ntop_state_t s; make_state(&s);
    conn_rebuild_idx(&s);
    view_conns_draw(&s);
}

static void test_draw_with_banner(void) {
    ntop_state_t s; make_state(&s);
    for (int p = 1024; p < 1032; p++)
        add_tcp_conn(&s, "1.1.1.1", (uint16_t)p);
    scan_update(&s);
    conn_rebuild_idx(&s);
    view_conns_draw(&s);
}

void run_scan_tests(void) {
    TEST_SUITE("scan");
    RUN_TEST(test_below_threshold_not_flagged);
    RUN_TEST(test_at_threshold_flagged);
    RUN_TEST(test_above_threshold_flagged);
    RUN_TEST(test_private_ip_ignored);
    RUN_TEST(test_loopback_ignored);
    RUN_TEST(test_link_local_ignored);
    RUN_TEST(test_cgnat_ignored);
    RUN_TEST(test_port_dedup);
    RUN_TEST(test_flagged_returns_port_count);
    RUN_TEST(test_unflagged_returns_zero);
    RUN_TEST(test_unknown_ip_returns_zero);
    RUN_TEST(test_ttl_expiry);
    RUN_TEST(test_udp_not_tracked);
    RUN_TEST(test_multiple_ips_independent);
    RUN_TEST(test_draw_no_scan);
    RUN_TEST(test_draw_with_banner);
}
