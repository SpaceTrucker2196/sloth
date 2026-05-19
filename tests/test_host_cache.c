#include <string.h>
#include "runner.h"
#include "host_cache.h"

static void test_empty_lookup_misses(void) {
    host_cache_clear();
    char buf[64];
    ASSERT_EQ(host_cache_lookup("1.2.3.4", buf, sizeof(buf)), 0);
    ASSERT_STR(buf, "");
    ASSERT_EQ(host_cache_count(), 0);
}

static void test_add_then_lookup(void) {
    host_cache_clear();
    host_cache_add("1.2.3.4", "example.com");
    char buf[64];
    ASSERT_EQ(host_cache_lookup("1.2.3.4", buf, sizeof(buf)), 1);
    ASSERT_STR(buf, "example.com");
    ASSERT_EQ(host_cache_count(), 1);
}

static void test_update_replaces_existing_host(void) {
    host_cache_clear();
    host_cache_add("8.8.8.8", "dns.google");
    host_cache_add("8.8.8.8", "google-public-dns-a.google.com");
    char buf[64];
    host_cache_lookup("8.8.8.8", buf, sizeof(buf));
    ASSERT_STR(buf, "google-public-dns-a.google.com");
    ASSERT_EQ(host_cache_count(), 1);
}

static void test_nxdomain_and_empty_are_dropped(void) {
    host_cache_clear();
    host_cache_add("1.1.1.1", "NXDOMAIN");
    host_cache_add("1.1.1.1", "");
    host_cache_add("",        "anything");
    ASSERT_EQ(host_cache_count(), 0);
}

static void test_multiple_ips_independent(void) {
    host_cache_clear();
    host_cache_add("10.0.0.1", "a.local");
    host_cache_add("10.0.0.2", "b.local");
    host_cache_add("10.0.0.3", "c.local");
    char buf[64];
    host_cache_lookup("10.0.0.2", buf, sizeof(buf));
    ASSERT_STR(buf, "b.local");
    host_cache_lookup("10.0.0.1", buf, sizeof(buf));
    ASSERT_STR(buf, "a.local");
    ASSERT_EQ(host_cache_count(), 3);
}

static void test_ring_overwrites_oldest_when_full(void) {
    host_cache_clear();
    /* Fill the cache. */
    char ip[32], host[32];
    for (int i = 0; i < HOST_CACHE_CAP; i++) {
        snprintf(ip,   sizeof(ip),   "10.%d.%d.%d",
                 (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        snprintf(host, sizeof(host), "h%d.local", i);
        host_cache_add(ip, host);
    }
    ASSERT_EQ(host_cache_count(), HOST_CACHE_CAP);

    /* The first entry is still present. */
    char buf[64];
    ASSERT_EQ(host_cache_lookup("10.0.0.0", buf, sizeof(buf)), 1);
    ASSERT_STR(buf, "h0.local");

    /* Add one more — count stays at cap, but the new entry is present. */
    host_cache_add("9.9.9.9", "newcomer");
    ASSERT_EQ(host_cache_count(), HOST_CACHE_CAP);
    ASSERT_EQ(host_cache_lookup("9.9.9.9", buf, sizeof(buf)), 1);
    ASSERT_STR(buf, "newcomer");
    /* And the oldest (h0.local) has been overwritten. */
    ASSERT_EQ(host_cache_lookup("10.0.0.0", buf, sizeof(buf)), 0);
}

static void test_lookup_handles_null_args(void) {
    host_cache_clear();
    host_cache_add("4.4.4.4", "ok.local");
    char buf[64];
    /* NULL ip / NULL out / zero size — none should crash, all miss. */
    ASSERT_EQ(host_cache_lookup(NULL,      buf, sizeof(buf)), 0);
    ASSERT_EQ(host_cache_lookup("4.4.4.4", NULL, sizeof(buf)), 0);
    ASSERT_EQ(host_cache_lookup("4.4.4.4", buf, 0),           0);
}

void run_host_cache_tests(void) {
    TEST_SUITE("host_cache");
    RUN_TEST(test_empty_lookup_misses);
    RUN_TEST(test_add_then_lookup);
    RUN_TEST(test_update_replaces_existing_host);
    RUN_TEST(test_nxdomain_and_empty_are_dropped);
    RUN_TEST(test_multiple_ips_independent);
    RUN_TEST(test_ring_overwrites_oldest_when_full);
    RUN_TEST(test_lookup_handles_null_args);
}
