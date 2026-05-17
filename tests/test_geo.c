#include <string.h>
#include "runner.h"
#include "geo.h"

/* ── geo_lookup (host byte order) ────────────────────────── */

static void test_private_10(void) {
    /* 10.0.0.1 = 0x0A000001 */
    ASSERT_STR(geo_lookup(0x0A000001u), "--");
}

static void test_private_10_last(void) {
    /* 10.255.255.255 = 0x0AFFFFFF */
    ASSERT_STR(geo_lookup(0x0AFFFFFEu), "--");
}

static void test_private_172_16(void) {
    /* 172.16.0.1 = 0xAC100001 */
    ASSERT_STR(geo_lookup(0xAC100001u), "--");
}

static void test_private_172_31(void) {
    /* 172.31.255.255 = 0xAC1FFFFF */
    ASSERT_STR(geo_lookup(0xAC1FFFFEu), "--");
}

static void test_non_private_172_32(void) {
    /* 172.32.0.1 — outside RFC1918 172.16/12, should be US (ARIN) */
    const char *cc = geo_lookup(0xAC200001u);
    ASSERT(cc != NULL);
    ASSERT_STR(cc, "US");
}

static void test_private_192_168(void) {
    /* 192.168.1.1 = 0xC0A80101 */
    ASSERT_STR(geo_lookup(0xC0A80101u), "--");
}

static void test_loopback(void) {
    /* 127.0.0.1 = 0x7F000001 */
    ASSERT_STR(geo_lookup(0x7F000001u), "LO");
}

static void test_cgnat(void) {
    /* 100.64.0.1 = 0x64400001 */
    ASSERT_STR(geo_lookup(0x64400001u), "--");
}

static void test_cgnat_boundary_high(void) {
    /* 100.127.255.255 = 0x647FFFFF */
    ASSERT_STR(geo_lookup(0x647FFFFFu), "--");
}

static void test_cgnat_just_outside(void) {
    /* 100.128.0.1 = 0x64800001 — outside CGNAT range, ARIN */
    const char *cc = geo_lookup(0x64800001u);
    ASSERT_STR(cc, "US");
}

static void test_link_local(void) {
    /* 169.254.1.1 = 0xA9FE0101 */
    ASSERT_STR(geo_lookup(0xA9FE0101u), "--");
}

static void test_multicast(void) {
    /* 224.0.0.1 = 0xE0000001 */
    ASSERT_STR(geo_lookup(0xE0000001u), "MC");
}

static void test_multicast_high(void) {
    /* 239.255.255.255 = 0xEFFFFFFF */
    ASSERT_STR(geo_lookup(0xEFFFFFFFu), "MC");
}

static void test_reserved(void) {
    /* 240.0.0.1 = 0xF0000001 */
    ASSERT_STR(geo_lookup(0xF0000001u), "--");
}

static void test_broadcast(void) {
    /* 255.255.255.255 = 0xFFFFFFFF */
    ASSERT_STR(geo_lookup(0xFFFFFFFFu), "--");
}

/* ── /8 assignments ──────────────────────────────────────── */

static void test_arin_8(void) {
    /* 8.8.8.8 = 0x08080808 → ARIN */
    ASSERT_STR(geo_lookup(0x08080808u), "US");
}

static void test_arin_34(void) {
    /* 34.1.2.3 → Google / ARIN */
    ASSERT_STR(geo_lookup(0x22010203u), "US");
}

static void test_apnic_1(void) {
    /* 1.2.3.4 = 0x01020304 → APNIC */
    ASSERT_STR(geo_lookup(0x01020304u), "AP");
}

static void test_apnic_58(void) {
    /* 58.1.2.3 → APNIC */
    ASSERT_STR(geo_lookup(0x3A010203u), "AP");
}

static void test_apnic_119(void) {
    /* 119.1.2.3 → APNIC */
    ASSERT_STR(geo_lookup(0x77010203u), "AP");
}

static void test_ripe_80(void) {
    /* 80.1.2.3 → RIPE NCC */
    ASSERT_STR(geo_lookup(0x50010203u), "EU");
}

static void test_ripe_185(void) {
    /* 185.1.2.3 → RIPE NCC */
    ASSERT_STR(geo_lookup(0xB9010203u), "EU");
}

static void test_lacnic_177(void) {
    /* 177.1.2.3 → LACNIC (Brazil) */
    ASSERT_STR(geo_lookup(0xB1010203u), "SA");
}

static void test_lacnic_200(void) {
    /* 200.1.2.3 → LACNIC */
    ASSERT_STR(geo_lookup(0xC8010203u), "SA");
}

static void test_afrinic_41(void) {
    /* 41.1.2.3 → AFRINIC */
    ASSERT_STR(geo_lookup(0x29010203u), "AF");
}

static void test_afrinic_196(void) {
    /* 196.1.2.3 → AFRINIC */
    ASSERT_STR(geo_lookup(0xC4010203u), "AF");
}

/* ── geo_lookup_str ──────────────────────────────────────── */

static void test_str_us(void) {
    const char *cc = geo_lookup_str("8.8.8.8");
    ASSERT(cc != NULL);
    ASSERT_STR(cc, "US");
}

static void test_str_private(void) {
    ASSERT_STR(geo_lookup_str("10.0.0.1"), "--");
}

static void test_str_loopback(void) {
    ASSERT_STR(geo_lookup_str("127.0.0.1"), "LO");
}

static void test_str_multicast(void) {
    ASSERT_STR(geo_lookup_str("224.0.0.5"), "MC");
}

static void test_str_apnic(void) {
    ASSERT_STR(geo_lookup_str("1.1.1.1"), "AP");
}

static void test_str_ipv6_null(void) {
    /* IPv6 → NULL */
    ASSERT(geo_lookup_str("2001:db8::1") == NULL);
}

static void test_str_invalid_null(void) {
    ASSERT(geo_lookup_str("not.an.ip") == NULL);
}

static void test_str_null_ptr(void) {
    ASSERT(geo_lookup_str(NULL) == NULL);
}

static void test_str_empty_null(void) {
    ASSERT(geo_lookup_str("") == NULL);
}

/* ── Entry point ─────────────────────────────────────────── */

void run_geo_tests(void) {
    TEST_SUITE("geo/private");
    RUN_TEST(test_private_10);
    RUN_TEST(test_private_10_last);
    RUN_TEST(test_private_172_16);
    RUN_TEST(test_private_172_31);
    RUN_TEST(test_non_private_172_32);
    RUN_TEST(test_private_192_168);
    RUN_TEST(test_loopback);
    RUN_TEST(test_cgnat);
    RUN_TEST(test_cgnat_boundary_high);
    RUN_TEST(test_cgnat_just_outside);
    RUN_TEST(test_link_local);
    RUN_TEST(test_multicast);
    RUN_TEST(test_multicast_high);
    RUN_TEST(test_reserved);
    RUN_TEST(test_broadcast);

    TEST_SUITE("geo/8blocks");
    RUN_TEST(test_arin_8);
    RUN_TEST(test_arin_34);
    RUN_TEST(test_apnic_1);
    RUN_TEST(test_apnic_58);
    RUN_TEST(test_apnic_119);
    RUN_TEST(test_ripe_80);
    RUN_TEST(test_ripe_185);
    RUN_TEST(test_lacnic_177);
    RUN_TEST(test_lacnic_200);
    RUN_TEST(test_afrinic_41);
    RUN_TEST(test_afrinic_196);

    TEST_SUITE("geo/str");
    RUN_TEST(test_str_us);
    RUN_TEST(test_str_private);
    RUN_TEST(test_str_loopback);
    RUN_TEST(test_str_multicast);
    RUN_TEST(test_str_apnic);
    RUN_TEST(test_str_ipv6_null);
    RUN_TEST(test_str_invalid_null);
    RUN_TEST(test_str_null_ptr);
    RUN_TEST(test_str_empty_null);
}
