#include <string.h>
#include "runner.h"
#include "ip_owner.h"
#include "geo.h"

/* ── ip_owner_lookup_str ─────────────────────────────────── */

static void test_cloudflare_dns(void) {
    const char *o = ip_owner_lookup_str("1.1.1.1");
    ASSERT(o != NULL);
    ASSERT_STR(o, "Cloudflare DNS");
}

static void test_google_dns(void) {
    const char *o = ip_owner_lookup_str("8.8.8.8");
    ASSERT(o != NULL);
    ASSERT_STR(o, "Google DNS");
    o = ip_owner_lookup_str("8.8.4.4");
    ASSERT_STR(o, "Google DNS");
}

static void test_quad9(void) {
    ASSERT_STR(ip_owner_lookup_str("9.9.9.9"), "Quad9");
    ASSERT_STR(ip_owner_lookup_str("149.112.112.112"), "Quad9");
}

static void test_apple(void) {
    /* anywhere in 17.0.0.0/8 */
    const char *o = ip_owner_lookup_str("17.253.144.10");
    ASSERT(o != NULL);
    ASSERT_STR(o, "Apple");
}

static void test_github(void) {
    /* 140.82.112.0/20 covers github.com itself */
    const char *o = ip_owner_lookup_str("140.82.121.4");
    ASSERT(o != NULL);
    ASSERT_STR(o, "GitHub");
    ASSERT_STR(ip_owner_lookup_str("185.199.108.153"), "GitHub Pages");
}

static void test_cloudflare_proxy(void) {
    ASSERT_STR(ip_owner_lookup_str("104.16.132.229"), "Cloudflare");
    ASSERT_STR(ip_owner_lookup_str("172.67.0.1"),     "Cloudflare");
}

static void test_aws_cloudfront(void) {
    /* 13.32.0.0/15 */
    ASSERT_STR(ip_owner_lookup_str("13.32.0.5"),  "AWS CloudFront");
    ASSERT_STR(ip_owner_lookup_str("13.33.99.1"), "AWS CloudFront");
}

static void test_meta_known_ranges(void) {
    ASSERT_STR(ip_owner_lookup_str("31.13.65.36"),   "Meta");
    ASSERT_STR(ip_owner_lookup_str("157.240.22.35"), "Meta");
}

/* ── Misses ──────────────────────────────────────────────── */

static void test_private_address_returns_null(void) {
    ASSERT(ip_owner_lookup_str("192.168.1.1") == NULL);
    ASSERT(ip_owner_lookup_str("10.0.0.5")    == NULL);
    ASSERT(ip_owner_lookup_str("172.16.0.1")  == NULL);
}

static void test_obscure_public_ip_returns_null(void) {
    /* RFC 5737 documentation range — definitely not in our owner table */
    ASSERT(ip_owner_lookup_str("203.0.113.99") == NULL);
}

static void test_ipv6_returns_null(void) {
    ASSERT(ip_owner_lookup_str("2606:4700:4700::1111") == NULL);
    ASSERT(ip_owner_lookup_str("fe80::1")              == NULL);
}

static void test_invalid_input_returns_null(void) {
    ASSERT(ip_owner_lookup_str(NULL)         == NULL);
    ASSERT(ip_owner_lookup_str("")           == NULL);
    ASSERT(ip_owner_lookup_str("not-an-ip")  == NULL);
    ASSERT(ip_owner_lookup_str("256.1.1.1")  == NULL);
}

/* ── geo_region_name ─────────────────────────────────────── */

static void test_region_name_us(void) {
    const char *name = geo_region_name(geo_lookup_str("8.8.8.8"));
    ASSERT(name != NULL);
    ASSERT_STR(name, "ARIN (US/CA)");
}

static void test_region_name_apnic(void) {
    const char *name = geo_region_name(geo_lookup_str("1.1.1.1"));
    ASSERT(name != NULL);
    ASSERT_STR(name, "APNIC (Asia-Pac)");
}

static void test_region_name_private(void) {
    const char *name = geo_region_name(geo_lookup_str("192.168.1.1"));
    ASSERT(name != NULL);
    ASSERT_STR(name, "Private / Reserved");
}

static void test_region_name_null_inputs(void) {
    ASSERT(geo_region_name(NULL) == NULL);
    ASSERT(geo_region_name("ZZ") == NULL);   /* unknown code */
}

void run_ip_owner_tests(void) {
    TEST_SUITE("ip_owner well-known");
    RUN_TEST(test_cloudflare_dns);
    RUN_TEST(test_google_dns);
    RUN_TEST(test_quad9);
    RUN_TEST(test_apple);
    RUN_TEST(test_github);
    RUN_TEST(test_cloudflare_proxy);
    RUN_TEST(test_aws_cloudfront);
    RUN_TEST(test_meta_known_ranges);

    TEST_SUITE("ip_owner misses");
    RUN_TEST(test_private_address_returns_null);
    RUN_TEST(test_obscure_public_ip_returns_null);
    RUN_TEST(test_ipv6_returns_null);
    RUN_TEST(test_invalid_input_returns_null);

    TEST_SUITE("geo_region_name");
    RUN_TEST(test_region_name_us);
    RUN_TEST(test_region_name_apnic);
    RUN_TEST(test_region_name_private);
    RUN_TEST(test_region_name_null_inputs);
}
