#include <string.h>
#include <stdio.h>
#include "runner.h"
#include "dns.h"

/* ── Tests ───────────────────────────────────────────────── */

static void test_cache_miss_returns_ip(void) {
    dns_reset();
    /* Unknown IP: async resolve pending — raw IP returned immediately */
    ASSERT_STR(dns_lookup("192.0.2.1"), "192.0.2.1");
}

static void test_dedup_pending(void) {
    dns_reset();
    /* Two lookups for same IP must not crash or corrupt queue */
    ASSERT_STR(dns_lookup("198.51.100.1"), "198.51.100.1");
    ASSERT_STR(dns_lookup("198.51.100.1"), "198.51.100.1");
}

static void test_inject_resolved(void) {
    dns_reset();
    dns_set_resolved("10.0.0.1", "myhost");
    ASSERT_STR(dns_lookup("10.0.0.1"), "myhost");
}

static void test_inject_then_fmt_addr(void) {
    dns_reset();
    dns_set_resolved("10.0.0.2", "router");
    char buf[64];
    dns_fmt_addr("10.0.0.2", 80, buf, sizeof(buf));
    ASSERT_STR(buf, "router:80");
}

static void test_fmt_addr_no_entry(void) {
    dns_reset();
    char buf[64];
    dns_fmt_addr("203.0.113.5", 443, buf, sizeof(buf));
    /* Not resolved yet — raw IP:port */
    ASSERT_STR(buf, "203.0.113.5:443");
}

static void test_reset_clears_cache(void) {
    dns_reset();
    dns_set_resolved("10.1.1.1", "before-reset");
    dns_reset();
    /* After reset the entry is gone — lookup returns raw IP */
    ASSERT_STR(dns_lookup("10.1.1.1"), "10.1.1.1");
}

static void test_ipv6_miss_returns_ip(void) {
    dns_reset();
    ASSERT_STR(dns_lookup("2001:db8::1"), "2001:db8::1");
}

static void test_inject_ipv6(void) {
    dns_reset();
    dns_set_resolved("::1", "localhost6");
    ASSERT_STR(dns_lookup("::1"), "localhost6");
}

static void test_multiple_distinct_ips(void) {
    dns_reset();
    dns_set_resolved("1.1.1.1", "one.one.one.one");
    dns_set_resolved("8.8.8.8", "dns.google");
    ASSERT_STR(dns_lookup("1.1.1.1"), "one.one.one.one");
    ASSERT_STR(dns_lookup("8.8.8.8"), "dns.google");
}

/* ── Entry point ─────────────────────────────────────────── */

void run_dns_tests(void) {
    TEST_SUITE("DNS cache");
    RUN_TEST(test_cache_miss_returns_ip);
    RUN_TEST(test_dedup_pending);
    RUN_TEST(test_inject_resolved);
    RUN_TEST(test_inject_then_fmt_addr);
    RUN_TEST(test_fmt_addr_no_entry);
    RUN_TEST(test_reset_clears_cache);
    RUN_TEST(test_ipv6_miss_returns_ip);
    RUN_TEST(test_inject_ipv6);
    RUN_TEST(test_multiple_distinct_ips);
}
