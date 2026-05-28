#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "scan.h"
#include "views/conns.h"
#include "runner.h"

static void make_state(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
}

static void add_tcp_conn(sloth_state_t *s, const char *remote, uint16_t lport) {
    int i = s->conn_count++;
    s->conns[i].proto = PROTO_TCP;
    snprintf(s->conns[i].remote_addr, sizeof(s->conns[i].remote_addr), "%s", remote);
    s->conns[i].local_port  = lport;
    s->conns[i].remote_port = 443;
    snprintf(s->conns[i].local_addr, sizeof(s->conns[i].local_addr), "192.168.1.10");
}

static void test_below_threshold_not_flagged(void) {
    sloth_state_t s; make_state(&s);
    for (int p = 1024; p < 1031; p++)
        add_tcp_conn(&s, "1.2.3.4", (uint16_t)p);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "1.2.3.4") == 0);
}

static void test_at_threshold_flagged(void) {
    sloth_state_t s; make_state(&s);
    for (int p = 1024; p < 1032; p++)
        add_tcp_conn(&s, "1.2.3.4", (uint16_t)p);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "1.2.3.4") > 0);
}

static void test_above_threshold_flagged(void) {
    sloth_state_t s; make_state(&s);
    for (int p = 1024; p < 1040; p++)
        add_tcp_conn(&s, "5.6.7.8", (uint16_t)p);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "5.6.7.8") > 0);
}

static void test_private_ip_ignored(void) {
    sloth_state_t s; make_state(&s);
    for (int p = 1024; p < 1040; p++)
        add_tcp_conn(&s, "192.168.1.200", (uint16_t)p);
    scan_update(&s);
    ASSERT(s.scan_count == 0);
}

static void test_loopback_ignored(void) {
    sloth_state_t s; make_state(&s);
    for (int p = 1024; p < 1040; p++)
        add_tcp_conn(&s, "127.0.0.1", (uint16_t)p);
    scan_update(&s);
    ASSERT(s.scan_count == 0);
}

static void test_link_local_ignored(void) {
    sloth_state_t s; make_state(&s);
    for (int p = 1024; p < 1040; p++)
        add_tcp_conn(&s, "169.254.1.1", (uint16_t)p);
    scan_update(&s);
    ASSERT(s.scan_count == 0);
}

static void test_cgnat_ignored(void) {
    sloth_state_t s; make_state(&s);
    for (int p = 1024; p < 1040; p++)
        add_tcp_conn(&s, "100.100.1.1", (uint16_t)p);
    scan_update(&s);
    ASSERT(s.scan_count == 0);
}

static void test_port_dedup(void) {
    sloth_state_t s; make_state(&s);
    for (int i = 0; i < 20; i++)
        add_tcp_conn(&s, "8.8.8.8", 80);
    scan_update(&s);
    ASSERT(s.scan_count == 1);
    ASSERT(s.scan_entries[0].port_count == 1);
    ASSERT(scan_is_flagged(&s, "8.8.8.8") == 0);
}

static void test_flagged_returns_port_count(void) {
    sloth_state_t s; make_state(&s);
    for (int p = 1024; p < 1032; p++)
        add_tcp_conn(&s, "203.0.113.1", (uint16_t)p);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "203.0.113.1") >= 8);
}

static void test_unflagged_returns_zero(void) {
    sloth_state_t s; make_state(&s);
    add_tcp_conn(&s, "1.2.3.4", 80);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "1.2.3.4") == 0);
}

static void test_unknown_ip_returns_zero(void) {
    sloth_state_t s; make_state(&s);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "9.9.9.9") == 0);
}

static void test_ttl_expiry(void) {
    sloth_state_t s; make_state(&s);
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
    sloth_state_t s; make_state(&s);
    for (int p = 1024; p < 1040; p++) {
        int i = s.conn_count++;
        s.conns[i].proto = PROTO_UDP;
        snprintf(s.conns[i].remote_addr, 46, "1.2.3.4");
        s.conns[i].local_port = (uint16_t)p;
    }
    scan_update(&s);
    ASSERT(s.scan_count == 0);
}

/* Comprehensive boundary sweep over scan_is_routable's RFC1918 /
 * loopback / link-local / CGNAT / multicast filters (lines 16-22 of
 * src/scan.c). For each non-routable range we test:
 *   - one IP just *inside* the range (not flagged)
 *   - one IP just *outside* on each side (flagged when port count hits
 *     threshold)
 * Kills the bulk of the const ±1 and rel `>=`→`>` / `<=`→`<` mutations
 * on the routability filter — they all change which side of a boundary
 * an IP falls on. */
static void routable_seed_then_assert(const char *ip, int expect_count) {
    sloth_state_t s; make_state(&s);
    for (int p = 1024; p < 1024 + SCAN_PORT_THRESH; p++)
        add_tcp_conn(&s, ip, (uint16_t)p);
    scan_update(&s);
    if (expect_count == 0) {
        ASSERT(s.scan_count == 0);
    } else {
        ASSERT(scan_is_flagged(&s, ip) >= SCAN_PORT_THRESH);
    }
}

static void test_routable_boundary_10_8(void) {
    /* 10.0.0.0/8 — RFC1918 */
    routable_seed_then_assert("9.255.255.255", 1);   /* just below — routable */
    routable_seed_then_assert("10.0.0.1",      0);   /* just inside */
    routable_seed_then_assert("11.0.0.1",      1);   /* just above */
}

static void test_routable_boundary_172_12(void) {
    /* 172.16.0.0/12 — RFC1918 */
    routable_seed_then_assert("172.15.255.1",  1);   /* outside low */
    routable_seed_then_assert("172.16.0.1",    0);   /* inside low edge */
    routable_seed_then_assert("172.31.255.1",  0);   /* inside high edge */
    routable_seed_then_assert("172.32.0.1",    1);   /* outside high */
}

static void test_routable_boundary_192_168(void) {
    /* 192.168.0.0/16 — RFC1918 */
    routable_seed_then_assert("192.167.0.1",   1);
    routable_seed_then_assert("192.168.0.1",   0);
    routable_seed_then_assert("192.169.0.1",   1);
}

static void test_routable_boundary_cgnat(void) {
    /* 100.64.0.0/10 — CGNAT */
    routable_seed_then_assert("100.63.0.1",    1);   /* outside low */
    routable_seed_then_assert("100.64.0.1",    0);   /* inside low edge */
    routable_seed_then_assert("100.127.255.1", 0);   /* inside high edge */
    routable_seed_then_assert("100.128.0.1",   1);   /* outside high */
}

static void test_routable_boundary_loopback(void) {
    routable_seed_then_assert("126.255.255.1", 1);
    routable_seed_then_assert("127.0.0.1",     0);
    routable_seed_then_assert("128.0.0.1",     1);
}

static void test_routable_boundary_link_local(void) {
    /* 169.254.0.0/16 — only triggers when first octet AND second match */
    routable_seed_then_assert("169.253.0.1",   1);
    routable_seed_then_assert("169.254.0.1",   0);
    routable_seed_then_assert("169.255.0.1",   1);
}

static void test_routable_boundary_multicast(void) {
    /* 224.0.0.0/4 plus reserved 240+ all rejected via `a >= 224`. */
    routable_seed_then_assert("223.255.255.1", 1);   /* below — routable */
    routable_seed_then_assert("224.0.0.1",     0);   /* multicast */
    routable_seed_then_assert("239.255.255.1", 0);   /* still multicast */
    routable_seed_then_assert("240.0.0.1",     0);   /* reserved */
}

/* Kills the line-15 `sscanf < 2` mutation (`2 -> 1`): a malformed IP
 * with fewer than two parseable octets must be rejected outright. */
static void test_routable_rejects_malformed_ips(void) {
    sloth_state_t s;
    /* Single octet: sscanf returns 1. */
    make_state(&s);
    for (int p = 1024; p < 1024 + SCAN_PORT_THRESH; p++)
        add_tcp_conn(&s, "100", (uint16_t)p);
    scan_update(&s);
    ASSERT(s.scan_count == 0);

    /* Empty string is already filtered by the earlier `remote_addr[0]`
     * guard, but try non-numeric content here too. */
    make_state(&s);
    for (int p = 1024; p < 1024 + SCAN_PORT_THRESH; p++)
        add_tcp_conn(&s, "abc", (uint16_t)p);
    scan_update(&s);
    ASSERT(s.scan_count == 0);
}

static void test_multiple_ips_independent(void) {
    sloth_state_t s; make_state(&s);
    for (int p = 1024; p < 1032; p++) add_tcp_conn(&s, "203.0.113.10", (uint16_t)p);
    for (int p = 1024; p < 1028; p++) add_tcp_conn(&s, "203.0.113.20", (uint16_t)p);
    scan_update(&s);
    ASSERT(scan_is_flagged(&s, "203.0.113.10") > 0);
    ASSERT(scan_is_flagged(&s, "203.0.113.20") == 0);
}

static void test_draw_no_scan(void) {
    sloth_state_t s; make_state(&s);
    conn_rebuild_idx(&s);
    view_conns_draw(&s);
}

static void test_draw_with_banner(void) {
    sloth_state_t s; make_state(&s);
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
    RUN_TEST(test_routable_boundary_10_8);
    RUN_TEST(test_routable_boundary_172_12);
    RUN_TEST(test_routable_boundary_192_168);
    RUN_TEST(test_routable_boundary_cgnat);
    RUN_TEST(test_routable_boundary_loopback);
    RUN_TEST(test_routable_boundary_link_local);
    RUN_TEST(test_routable_boundary_multicast);
    RUN_TEST(test_routable_rejects_malformed_ips);
    RUN_TEST(test_multiple_ips_independent);
    RUN_TEST(test_draw_no_scan);
    RUN_TEST(test_draw_with_banner);
}
