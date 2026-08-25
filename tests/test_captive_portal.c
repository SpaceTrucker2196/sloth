#include <string.h>
#include "runner.h"
#include "captive_portal.h"

/*
 * Captive-portal interception — issue #69.
 *
 * The sentinels are published, fixed values, so unlike the tool
 * fingerprints in #68 this table ships full. What these tests pin is
 * the thing that is easy to get wrong: **when the detector is allowed
 * to speak.** A body sloth did not see whole cannot be compared, and a
 * comparison made anyway turns every large page into a reported hijack.
 */

static void mk_resp(http_log_entry_t *e, const char *host, const char *path,
                    uint16_t status, const char *body, int complete) {
    memset(e, 0, sizeof(*e));
    e->is_response = 1;
    e->status = status;
    snprintf(e->host, sizeof(e->host), "%s", host);
    snprintf(e->path, sizeof(e->path), "%s", path);
    if (body) {
        int n = (int)strlen(body);
        if (n > HTTP_RESP_BODY_MAX) n = HTTP_RESP_BODY_MAX;
        memcpy(e->resp_body, body, (size_t)n);
        e->resp_body_len = n;
        e->content_length = n;
    }
    e->body_complete = complete;
}

static const char *APPLE_OK =
    "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>";

/* ── the body check ── */

static void test_correct_apple_sentinel_is_quiet(void) {
    http_log_entry_t e;
    mk_resp(&e, "captive.apple.com", "/hotspot-detect.html", 200,
            APPLE_OK, 1);
    ASSERT_EQ(cp_check_response(&e), 0);
}

static void test_wrong_apple_body_is_a_hijack(void) {
    http_log_entry_t e;
    mk_resp(&e, "captive.apple.com", "/hotspot-detect.html", 200,
            "<html>Sign in to continue</html>", 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
}

static void test_redirect_on_the_sentinel_is_a_hijack(void) {
    /* The classic portal: a 302 to the login page. */
    http_log_entry_t e;
    mk_resp(&e, "captive.apple.com", "/hotspot-detect.html", 302, "", 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
}

static void test_incomplete_body_never_fires(void) {
    /* **The assertion this detector rests on.** sloth does not
     * reassemble TCP, so a prefix that differs from the sentinel is
     * evidence of a segment boundary, not of interception. Comparing
     * anyway would report every large page on port 80 as a hijack. */
    http_log_entry_t e;
    mk_resp(&e, "captive.apple.com", "/hotspot-detect.html", 200,
            "<html>Sign in to continue</html>", 0 /* incomplete */);
    ASSERT_EQ(cp_check_response(&e), 0);
}

static void test_google_204_with_a_body_is_a_hijack(void) {
    /* A 204 that arrives with content is not a 204. */
    http_log_entry_t e;
    mk_resp(&e, "connectivitycheck.gstatic.com", "/generate_204", 204,
            "redirecting", 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);

    mk_resp(&e, "connectivitycheck.gstatic.com", "/generate_204", 204,
            NULL, 1);
    ASSERT_EQ(cp_check_response(&e), 0);
}

static void test_google_wrong_status_is_a_hijack(void) {
    http_log_entry_t e;
    mk_resp(&e, "connectivitycheck.gstatic.com", "/generate_204", 200,
            NULL, 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
}

static void test_microsoft_and_firefox_sentinels(void) {
    http_log_entry_t e;
    mk_resp(&e, "www.msftconnecttest.com", "/connecttest.txt", 200,
            "Microsoft Connect Test", 1);
    ASSERT_EQ(cp_check_response(&e), 0);
    mk_resp(&e, "www.msftconnecttest.com", "/connecttest.txt", 200,
            "Microsoft Connect Test\n", 1);      /* one byte different */
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);

    mk_resp(&e, "detectportal.firefox.com", "/success.txt", 200,
            "success\n", 1);
    ASSERT_EQ(cp_check_response(&e), 0);
}

static void test_non_sentinel_host_is_ignored(void) {
    /* Ordinary web traffic must not be compared against anything. */
    http_log_entry_t e;
    mk_resp(&e, "example.com", "/index.html", 200, "anything at all", 1);
    ASSERT_EQ(cp_check_response(&e), 0);
}

static void test_sentinel_host_wrong_path_is_ignored(void) {
    http_log_entry_t e;
    mk_resp(&e, "captive.apple.com", "/library/test/success.html", 200,
            "something else", 1);
    ASSERT_EQ(cp_check_response(&e), 0);
}

static void test_host_match_is_case_insensitive(void) {
    http_log_entry_t e;
    mk_resp(&e, "CAPTIVE.APPLE.COM", "/hotspot-detect.html", 200,
            "wrong", 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
}

static void test_path_prefix_tolerates_a_cache_buster(void) {
    http_log_entry_t e;
    mk_resp(&e, "detectportal.firefox.com", "/success.txt?ipv4", 200,
            "success\n", 1);
    ASSERT_EQ(cp_check_response(&e), 0);
}

/* ── the DNS check ── */

static void test_sentinel_resolving_into_private_space(void) {
    ASSERT_EQ(cp_check_dns("captive.apple.com", "192.168.1.1"),
              CP_KIND_DNS_SPOOF);
    ASSERT_EQ(cp_check_dns("captive.apple.com", "10.0.0.1"),
              CP_KIND_DNS_SPOOF);
    ASSERT_EQ(cp_check_dns("captive.apple.com", "172.16.5.9"),
              CP_KIND_DNS_SPOOF);
    /* CGNAT — a carrier or a portal appliance, and either way not Apple. */
    ASSERT_EQ(cp_check_dns("captive.apple.com", "100.64.3.2"),
              CP_KIND_DNS_SPOOF);
}

static void test_172_range_boundaries(void) {
    /* 172.16-31 is private; 172.15 and 172.32 are not. Getting this
     * wrong either misses a portal or accuses a public host. */
    ASSERT_EQ(cp_check_dns("captive.apple.com", "172.15.0.1"),
              CP_KIND_DNS_UNEXPECTED);
    ASSERT_EQ(cp_check_dns("captive.apple.com", "172.32.0.1"),
              CP_KIND_DNS_UNEXPECTED);
    ASSERT_EQ(cp_check_dns("captive.apple.com", "172.31.255.254"),
              CP_KIND_DNS_SPOOF);
}

static void test_apple_public_range_is_clean(void) {
    ASSERT_EQ(cp_check_dns("captive.apple.com", "17.253.144.10"), 0);
}

static void test_apple_outside_its_range_is_unexpected_not_spoof(void) {
    /* Being wrong about a CDN range must not produce a CRIT. */
    ASSERT_EQ(cp_check_dns("captive.apple.com", "93.184.216.34"),
              CP_KIND_DNS_UNEXPECTED);
}

static void test_non_sentinel_dns_ignored(void) {
    ASSERT_EQ(cp_check_dns("example.com", "192.168.1.1"), 0);
}

static void test_nxdomain_is_not_an_address(void) {
    ASSERT_EQ(cp_check_dns("captive.apple.com", "NXDOMAIN"), 0);
    ASSERT_EQ(cp_check_dns("captive.apple.com", ""), 0);
}

static void test_ipv6_private_ranges(void) {
    ASSERT_EQ(cp_check_dns("captive.apple.com", "fd00::1"),
              CP_KIND_DNS_SPOOF);
    ASSERT_EQ(cp_check_dns("captive.apple.com", "fe80::1"),
              CP_KIND_DNS_SPOOF);
    /* A public v6 address gets no opinion — the range lists are v4. */
    ASSERT_EQ(cp_check_dns("captive.apple.com", "2001:db8::1"), 0);
}

/* ── the TLS check ── */

static void test_sentinel_tls_to_a_private_address(void) {
    ASSERT_EQ(cp_check_tls("captive.apple.com", "192.168.1.1"),
              CP_KIND_TLS_MITM);
}

static void test_sentinel_tls_to_a_public_address_is_clean(void) {
    ASSERT_EQ(cp_check_tls("captive.apple.com", "17.253.144.10"), 0);
}

static void test_non_sentinel_tls_ignored(void) {
    /* Plenty of legitimate services live on private addresses. */
    ASSERT_EQ(cp_check_tls("intranet.example", "192.168.1.1"), 0);
}

/* ── the event ring ── */

static void test_events_recorded_newest_first(void) {
    cp_clear();
    cp_record(CP_KIND_HIJACK,    "captive.apple.com", "10.0.0.5", "a", 100);
    cp_record(CP_KIND_DNS_SPOOF, "www.gstatic.com",   "10.0.0.6", "b", 200);
    ASSERT_EQ(cp_event_count(), 2);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cp_snapshot(&s);
    ASSERT_EQ(s.cp_event_count, 2);
    ASSERT_STR(s.cp_events[0].host, "www.gstatic.com");
    ASSERT_STR(s.cp_events[1].host, "captive.apple.com");
    cp_clear();
}

static void test_zero_kind_is_not_recorded(void) {
    cp_clear();
    cp_record(0, "captive.apple.com", "10.0.0.5", NULL, 100);
    ASSERT_EQ(cp_event_count(), 0);
    cp_clear();
}

static void test_every_kind_has_a_label(void) {
    ASSERT(cp_kind_label(CP_KIND_HIJACK)[0]         != '\0');
    ASSERT(cp_kind_label(CP_KIND_DNS_SPOOF)[0]      != '\0');
    ASSERT(cp_kind_label(CP_KIND_DNS_UNEXPECTED)[0] != '\0');
    ASSERT(cp_kind_label(CP_KIND_TLS_MITM)[0]       != '\0');
    ASSERT_STR(cp_kind_label(0), "");
}

static void test_sentinel_host_recognition(void) {
    ASSERT_EQ(cp_is_sentinel_host("captive.apple.com"), 1);
    ASSERT_EQ(cp_is_sentinel_host("detectportal.firefox.com"), 1);
    ASSERT_EQ(cp_is_sentinel_host("example.com"), 0);
    ASSERT_EQ(cp_is_sentinel_host(""), 0);
    ASSERT_EQ(cp_is_sentinel_host(NULL), 0);
}

void run_captive_portal_tests(void) {
    TEST_SUITE("captive-portal sentinel body check (#69)");
    RUN_TEST(test_correct_apple_sentinel_is_quiet);
    RUN_TEST(test_wrong_apple_body_is_a_hijack);
    RUN_TEST(test_redirect_on_the_sentinel_is_a_hijack);
    RUN_TEST(test_incomplete_body_never_fires);
    RUN_TEST(test_google_204_with_a_body_is_a_hijack);
    RUN_TEST(test_google_wrong_status_is_a_hijack);
    RUN_TEST(test_microsoft_and_firefox_sentinels);
    RUN_TEST(test_non_sentinel_host_is_ignored);
    RUN_TEST(test_sentinel_host_wrong_path_is_ignored);
    RUN_TEST(test_host_match_is_case_insensitive);
    RUN_TEST(test_path_prefix_tolerates_a_cache_buster);

    TEST_SUITE("captive-portal DNS check (#69)");
    RUN_TEST(test_sentinel_resolving_into_private_space);
    RUN_TEST(test_172_range_boundaries);
    RUN_TEST(test_apple_public_range_is_clean);
    RUN_TEST(test_apple_outside_its_range_is_unexpected_not_spoof);
    RUN_TEST(test_non_sentinel_dns_ignored);
    RUN_TEST(test_nxdomain_is_not_an_address);
    RUN_TEST(test_ipv6_private_ranges);

    TEST_SUITE("captive-portal TLS check (#69)");
    RUN_TEST(test_sentinel_tls_to_a_private_address);
    RUN_TEST(test_sentinel_tls_to_a_public_address_is_clean);
    RUN_TEST(test_non_sentinel_tls_ignored);

    TEST_SUITE("captive-portal event ring (#69)");
    RUN_TEST(test_events_recorded_newest_first);
    RUN_TEST(test_zero_kind_is_not_recorded);
    RUN_TEST(test_every_kind_has_a_label);
    RUN_TEST(test_sentinel_host_recognition);
}
