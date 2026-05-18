#include <string.h>
#include "runner.h"
#include "ip_color.h"
#include "sloth.h"

/* ── Categorisation ──────────────────────────────────────── */

static void test_categorize_tcp(void) {
    /* Generic TCP — not on a recognised app-layer port */
    ASSERT_EQ((int)pkt_categorize(6, 12345, 22), (int)PKT_CAT_TCP);
}

static void test_categorize_udp(void) {
    /* Generic UDP — not on 53/443/80 */
    ASSERT_EQ((int)pkt_categorize(17, 33445, 123), (int)PKT_CAT_UDP);
}

static void test_categorize_tls(void) {
    /* Port 443 in either direction, over TCP or UDP (QUIC) */
    ASSERT_EQ((int)pkt_categorize(6,  12345, 443),   (int)PKT_CAT_TLS);
    ASSERT_EQ((int)pkt_categorize(6,  443,   12345), (int)PKT_CAT_TLS);
    ASSERT_EQ((int)pkt_categorize(17, 33445, 443),   (int)PKT_CAT_TLS);
}

static void test_categorize_http(void) {
    /* Ports 80 / 8080 / 8000 over TCP */
    ASSERT_EQ((int)pkt_categorize(6, 12345, 80),   (int)PKT_CAT_HTTP);
    ASSERT_EQ((int)pkt_categorize(6, 80,    12345), (int)PKT_CAT_HTTP);
    ASSERT_EQ((int)pkt_categorize(6, 12345, 8080), (int)PKT_CAT_HTTP);
    ASSERT_EQ((int)pkt_categorize(6, 12345, 8000), (int)PKT_CAT_HTTP);
}

static void test_categorize_dns_either_direction(void) {
    /* DNS bumps the category regardless of L4 proto */
    ASSERT_EQ((int)pkt_categorize(17, 12345, 53), (int)PKT_CAT_DNS);
    ASSERT_EQ((int)pkt_categorize(17, 53,    12345), (int)PKT_CAT_DNS);
    ASSERT_EQ((int)pkt_categorize(6,  12345, 53), (int)PKT_CAT_DNS);
}

static void test_categorize_icmp_beats_port_match(void) {
    /* Even if (improbably) the ports look like 443, ICMP wins */
    ASSERT_EQ((int)pkt_categorize(1, 443, 443), (int)PKT_CAT_ICMP);
}

static void test_categorize_icmp(void) {
    ASSERT_EQ((int)pkt_categorize(1,  0, 0), (int)PKT_CAT_ICMP);
    ASSERT_EQ((int)pkt_categorize(58, 0, 0), (int)PKT_CAT_ICMP);
}

static void test_categorize_other(void) {
    ASSERT_EQ((int)pkt_categorize(50, 0, 0), (int)PKT_CAT_OTHER);
}

/* ── Color index ─────────────────────────────────────────── */

static void test_color_index_deterministic(void) {
    int a = ip_color_index("8.8.8.8");
    int b = ip_color_index("8.8.8.8");
    ASSERT_EQ(a, b);
    ASSERT(a >= 0 && a < IP_NUM_COLORS);
}

static void test_color_index_distinct_ips(void) {
    /* Most non-trivial pairs should hash to different buckets — not all,
     * but at least a handful out of these eight. */
    const char *ips[] = {
        "8.8.8.8", "1.1.1.1", "192.168.1.5", "10.0.0.1",
        "fe80::1", "172.16.0.5", "203.0.113.7", "204.79.197.220",
    };
    int seen[IP_NUM_COLORS] = {0};
    int distinct = 0;
    for (int i = 0; i < 8; i++) {
        int idx = ip_color_index(ips[i]);
        if (!seen[idx]) { seen[idx] = 1; distinct++; }
    }
    ASSERT(distinct >= 4);
}

static void test_color_index_null_or_empty(void) {
    ASSERT_EQ(ip_color_index(NULL), 0);
    ASSERT_EQ(ip_color_index(""),   0);
}

/* ── Cross-panel index ───────────────────────────────────── */

static void test_index_single_source_not_cross_panel(void) {
    ip_index_clear();
    ip_index_add("8.8.8.8", IP_SRC_DNS);
    ASSERT_EQ(ip_index_is_cross_panel("8.8.8.8"), 0);
}

static void test_index_two_sources_is_cross_panel(void) {
    ip_index_clear();
    ip_index_add("8.8.8.8", IP_SRC_DNS);
    ip_index_add("8.8.8.8", IP_SRC_CONN);
    ASSERT_EQ(ip_index_is_cross_panel("8.8.8.8"), 1);
}

static void test_index_same_source_twice_not_cross_panel(void) {
    /* Two calls with the same source bit OR together to a single bit. */
    ip_index_clear();
    ip_index_add("8.8.8.8", IP_SRC_DNS);
    ip_index_add("8.8.8.8", IP_SRC_DNS);
    ASSERT_EQ(ip_index_is_cross_panel("8.8.8.8"), 0);
}

static void test_index_unknown_ip_not_cross_panel(void) {
    ip_index_clear();
    ASSERT_EQ(ip_index_is_cross_panel("8.8.8.8"), 0);
}

static void test_index_null_and_empty_safe(void) {
    ip_index_clear();
    ip_index_add(NULL, IP_SRC_DNS);
    ip_index_add("",   IP_SRC_DNS);
    ASSERT_EQ(ip_index_is_cross_panel(NULL), 0);
    ASSERT_EQ(ip_index_is_cross_panel(""),   0);
}

/* ── Whole-state build ───────────────────────────────────── */

static void test_build_from_state(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    /* Seed an IP into two distinct sources */
    s.conn_count = 1;
    snprintf(s.conns[0].remote_addr, sizeof(s.conns[0].remote_addr), "8.8.8.8");
    s.dns_log_count = 1;
    snprintf(s.dns_log[0].answer, sizeof(s.dns_log[0].answer), "8.8.8.8");

    ip_index_build(&s);
    ASSERT_EQ(ip_index_is_cross_panel("8.8.8.8"), 1);
    /* An IP seen only in one source isn't cross-panel */
    snprintf(s.dns_log[0].src, sizeof(s.dns_log[0].src), "10.0.0.5");
    ip_index_build(&s);
    ASSERT_EQ(ip_index_is_cross_panel("10.0.0.5"), 0);
}

void run_ip_color_tests(void) {
    TEST_SUITE("ip_color pkt_categorize");
    RUN_TEST(test_categorize_tcp);
    RUN_TEST(test_categorize_udp);
    RUN_TEST(test_categorize_tls);
    RUN_TEST(test_categorize_http);
    RUN_TEST(test_categorize_dns_either_direction);
    RUN_TEST(test_categorize_icmp);
    RUN_TEST(test_categorize_icmp_beats_port_match);
    RUN_TEST(test_categorize_other);

    TEST_SUITE("ip_color index");
    RUN_TEST(test_color_index_deterministic);
    RUN_TEST(test_color_index_distinct_ips);
    RUN_TEST(test_color_index_null_or_empty);

    TEST_SUITE("ip_color cross-panel");
    RUN_TEST(test_index_single_source_not_cross_panel);
    RUN_TEST(test_index_two_sources_is_cross_panel);
    RUN_TEST(test_index_same_source_twice_not_cross_panel);
    RUN_TEST(test_index_unknown_ip_not_cross_panel);
    RUN_TEST(test_index_null_and_empty_safe);

    TEST_SUITE("ip_color whole-state build");
    RUN_TEST(test_build_from_state);
}
