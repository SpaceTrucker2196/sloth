#include <string.h>
#include "runner.h"
#include "threat_intel.h"

/* ── Domain matching ─────────────────────────────────────── */

static void test_domain_exact_match(void) {
    const char *ioc = NULL;
    ASSERT(ti_match_domain("malware.testing.com", &ioc));
    ASSERT(ioc != NULL);
    ASSERT_STR(ioc, "malware.testing.com");
}

static void test_domain_subdomain_match(void) {
    const char *ioc = NULL;
    ASSERT(ti_match_domain("foo.malware.testing.com", &ioc));
    ASSERT_STR(ioc, "malware.testing.com");
}

static void test_domain_case_insensitive(void) {
    const char *ioc = NULL;
    ASSERT(ti_match_domain("Phishing.TESTING.com", &ioc));
    ASSERT_STR(ioc, "phishing.testing.com");
}

static void test_domain_no_false_prefix_match(void) {
    /* "notevilcorp.example" should NOT match the "evilcorp.example" rule. */
    const char *ioc = NULL;
    ASSERT(!ti_match_domain("notevilcorp.example", &ioc));
}

static void test_domain_unknown(void) {
    const char *ioc = NULL;
    ASSERT(!ti_match_domain("google.com", &ioc));
}

static void test_domain_null_and_empty(void) {
    const char *ioc = NULL;
    ASSERT(!ti_match_domain(NULL, &ioc));
    ASSERT(!ti_match_domain("", &ioc));
}

static void test_domain_match_without_out_ptr(void) {
    /* matched pointer may be NULL */
    ASSERT(ti_match_domain("malware.testing.com", NULL));
}

/* ── IP matching ─────────────────────────────────────────── */

static void test_ip_exact(void) {
    const char *ioc = NULL;
    ASSERT(ti_match_ip("192.0.2.66", &ioc));
    ASSERT_STR(ioc, "192.0.2.66");
}

static void test_ip_no_match(void) {
    const char *ioc = NULL;
    ASSERT(!ti_match_ip("8.8.8.8", &ioc));
    ASSERT(!ti_match_ip("1.1.1.1", &ioc));
}

static void test_ip_no_partial(void) {
    /* substring of an IOC must not match. */
    const char *ioc = NULL;
    ASSERT(!ti_match_ip("192.0.2.6",  &ioc));
    ASSERT(!ti_match_ip("192.0.2.666", &ioc));
}

static void test_ip_null_and_empty(void) {
    const char *ioc = NULL;
    ASSERT(!ti_match_ip(NULL, &ioc));
    ASSERT(!ti_match_ip("",   &ioc));
}

void run_threat_intel_tests(void) {
    TEST_SUITE("threat_intel domain match");
    RUN_TEST(test_domain_exact_match);
    RUN_TEST(test_domain_subdomain_match);
    RUN_TEST(test_domain_case_insensitive);
    RUN_TEST(test_domain_no_false_prefix_match);
    RUN_TEST(test_domain_unknown);
    RUN_TEST(test_domain_null_and_empty);
    RUN_TEST(test_domain_match_without_out_ptr);

    TEST_SUITE("threat_intel ip match");
    RUN_TEST(test_ip_exact);
    RUN_TEST(test_ip_no_match);
    RUN_TEST(test_ip_no_partial);
    RUN_TEST(test_ip_null_and_empty);
}
