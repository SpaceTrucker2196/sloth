#include <string.h>
#include "runner.h"
#include "services.h"

static void test_svc_ssh(void) {
    ASSERT_STR(svc_name(22), "ssh");
}

static void test_svc_http(void) {
    ASSERT_STR(svc_name(80), "http");
}

static void test_svc_https(void) {
    ASSERT_STR(svc_name(443), "https");
}

static void test_svc_dns(void) {
    ASSERT_STR(svc_name(53), "dns");
}

static void test_svc_mdns(void) {
    ASSERT_STR(svc_name(5353), "mdns");
}

static void test_svc_redis(void) {
    ASSERT_STR(svc_name(6379), "redis");
}

static void test_svc_mysql(void) {
    ASSERT_STR(svc_name(3306), "mysql");
}

static void test_svc_mongodb(void) {
    ASSERT_STR(svc_name(27017), "mongodb");
}

static void test_svc_wireguard(void) {
    ASSERT_STR(svc_name(51820), "wireguard");
}

static void test_svc_unknown_low(void) {
    ASSERT(svc_name(1) == NULL);
}

static void test_svc_unknown_high(void) {
    ASSERT(svc_name(65535) == NULL);
}

static void test_svc_unknown_mid(void) {
    ASSERT(svc_name(12345) == NULL);
}

static void test_fmt_known(void) {
    char buf[64];
    svc_fmt_addr(buf, sizeof(buf), "192.168.1.1", 443);
    ASSERT_STR(buf, "192.168.1.1:https");
}

static void test_fmt_unknown(void) {
    char buf[64];
    svc_fmt_addr(buf, sizeof(buf), "10.0.0.1", 12345);
    ASSERT_STR(buf, "10.0.0.1:12345");
}

static void test_fmt_ssh(void) {
    char buf[64];
    svc_fmt_addr(buf, sizeof(buf), "0.0.0.0", 22);
    ASSERT_STR(buf, "0.0.0.0:ssh");
}

static void test_fmt_grpc(void) {
    char buf[64];
    svc_fmt_addr(buf, sizeof(buf), "127.0.0.1", 50051);
    ASSERT_STR(buf, "127.0.0.1:grpc");
}

static void test_svc_all_sequential(void) {
    /* Table must be sorted — verify a chain of sequential port lookups */
    ASSERT(svc_name(21)   != NULL);  /* ftp      */
    ASSERT(svc_name(22)   != NULL);  /* ssh      */
    ASSERT(svc_name(23)   != NULL);  /* telnet   */
    ASSERT(svc_name(25)   != NULL);  /* smtp     */
    ASSERT(svc_name(24)   == NULL);  /* not in table */
}

void run_services_tests(void) {
    TEST_SUITE("service name lookup");
    RUN_TEST(test_svc_ssh);
    RUN_TEST(test_svc_http);
    RUN_TEST(test_svc_https);
    RUN_TEST(test_svc_dns);
    RUN_TEST(test_svc_mdns);
    RUN_TEST(test_svc_redis);
    RUN_TEST(test_svc_mysql);
    RUN_TEST(test_svc_mongodb);
    RUN_TEST(test_svc_wireguard);
    RUN_TEST(test_svc_unknown_low);
    RUN_TEST(test_svc_unknown_high);
    RUN_TEST(test_svc_unknown_mid);

    TEST_SUITE("svc_fmt_addr");
    RUN_TEST(test_fmt_known);
    RUN_TEST(test_fmt_unknown);
    RUN_TEST(test_fmt_ssh);
    RUN_TEST(test_fmt_grpc);
    RUN_TEST(test_svc_all_sequential);
}
