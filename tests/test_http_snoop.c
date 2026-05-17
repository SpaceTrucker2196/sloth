#include <string.h>
#include "runner.h"
#include "http_snoop.h"

/* Helpers */
static int snoop(const char *req, char *host, int hostsz) {
    return http_snoop((const uint8_t *)req, (int)strlen(req), host, hostsz);
}

/* ── Method recognition ─────────────────────────────────────── */

static void test_get_simple(void) {
    char host[64];
    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("example.com", host);
}

static void test_post_method(void) {
    char host[64];
    const char *req = "POST /submit HTTP/1.1\r\nHost: post.example.com\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("post.example.com", host);
}

static void test_put_method(void) {
    char host[64];
    const char *req = "PUT /resource HTTP/1.1\r\nHost: put.example.com\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("put.example.com", host);
}

static void test_head_method(void) {
    char host[64];
    const char *req = "HEAD / HTTP/1.1\r\nHost: head.example.com\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("head.example.com", host);
}

static void test_delete_method(void) {
    char host[64];
    const char *req = "DELETE /item HTTP/1.1\r\nHost: del.example.com\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("del.example.com", host);
}

static void test_options_method(void) {
    char host[64];
    const char *req = "OPTIONS * HTTP/1.1\r\nHost: opts.example.com\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("opts.example.com", host);
}

static void test_patch_method(void) {
    char host[64];
    const char *req = "PATCH /data HTTP/1.1\r\nHost: patch.example.com\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("patch.example.com", host);
}

static void test_connect_method(void) {
    char host[64];
    const char *req = "CONNECT proxy.example.com:443 HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("proxy.example.com", host);
}

static void test_trace_method(void) {
    char host[64];
    const char *req = "TRACE / HTTP/1.1\r\nHost: trace.example.com\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("trace.example.com", host);
}

/* ── Rejection cases ────────────────────────────────────────── */

static void test_response_rejected(void) {
    char host[64] = "";
    const char *req = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    ASSERT_EQ(0, snoop(req, host, sizeof(host)));
}

static void test_unknown_method_rejected(void) {
    char host[64] = "";
    const char *req = "FOOBAR / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    ASSERT_EQ(0, snoop(req, host, sizeof(host)));
}

static void test_too_short(void) {
    char host[64] = "";
    /* less than 16 bytes */
    const char *req = "GET / HTTP/1";
    ASSERT_EQ(0, http_snoop((const uint8_t *)req, 12, host, sizeof(host)));
}

static void test_hostsz_too_small(void) {
    char host[64] = "";
    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    ASSERT_EQ(0, http_snoop((const uint8_t *)req, (int)strlen(req), host, 1));
}

/* ── Host header parsing ────────────────────────────────────── */

static void test_no_host_header(void) {
    char host[64] = "";
    const char *req = "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
    ASSERT_EQ(0, snoop(req, host, sizeof(host)));
}

static void test_host_with_port_stripped(void) {
    char host[64];
    const char *req = "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("example.com", host);
}

static void test_host_with_standard_port_stripped(void) {
    char host[64];
    const char *req = "GET / HTTP/1.1\r\nHost: example.com:80\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("example.com", host);
}

static void test_host_leading_whitespace(void) {
    char host[64];
    const char *req = "GET / HTTP/1.1\r\nHost:   spaced.example.com\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("spaced.example.com", host);
}

static void test_host_trailing_whitespace(void) {
    char host[64];
    /* trailing space before \r\n */
    const char *req = "GET / HTTP/1.1\r\nHost: trail.example.com  \r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("trail.example.com", host);
}

static void test_host_uppercase_header(void) {
    char host[64];
    const char *req = "GET / HTTP/1.1\r\nHOST: upper.example.com\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("upper.example.com", host);
}

static void test_host_mixed_case_header(void) {
    char host[64];
    const char *req = "GET / HTTP/1.1\r\nhOsT: mixed.example.com\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("mixed.example.com", host);
}

static void test_multiple_headers_before_host(void) {
    char host[64];
    const char *req =
        "GET /page HTTP/1.1\r\n"
        "Accept: text/html\r\n"
        "Accept-Encoding: gzip\r\n"
        "Connection: keep-alive\r\n"
        "Host: multi.example.com\r\n"
        "\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("multi.example.com", host);
}

static void test_blank_line_stops_search(void) {
    /* blank line comes before Host — Host is in body, not headers */
    char host[64] = "";
    const char *req =
        "GET / HTTP/1.1\r\n"
        "\r\n"
        "Host: body.example.com\r\n";
    ASSERT_EQ(0, snoop(req, host, sizeof(host)));
}

static void test_buf_truncation(void) {
    char host[8];  /* only 8 bytes */
    const char *req = "GET / HTTP/1.1\r\nHost: verylonghostname.example.com\r\n\r\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    /* truncated to 7 chars + NUL */
    ASSERT_EQ(7, (int)strlen(host));
    /* first 7 bytes match */
    ASSERT_EQ(0, strncmp("verylon", host, 7));
}

static void test_lf_only_line_endings(void) {
    /* Some clients send \n without \r */
    char host[64];
    const char *req = "GET / HTTP/1.1\nHost: lf.example.com\n\n";
    ASSERT_EQ(1, snoop(req, host, sizeof(host)));
    ASSERT_STR("lf.example.com", host);
}

/* ── Entry point ────────────────────────────────────────────── */

void run_http_snoop_tests(void) {
    TEST_SUITE("http_snoop");

    RUN_TEST(test_get_simple);
    RUN_TEST(test_post_method);
    RUN_TEST(test_put_method);
    RUN_TEST(test_head_method);
    RUN_TEST(test_delete_method);
    RUN_TEST(test_options_method);
    RUN_TEST(test_patch_method);
    RUN_TEST(test_connect_method);
    RUN_TEST(test_trace_method);

    RUN_TEST(test_response_rejected);
    RUN_TEST(test_unknown_method_rejected);
    RUN_TEST(test_too_short);
    RUN_TEST(test_hostsz_too_small);

    RUN_TEST(test_no_host_header);
    RUN_TEST(test_host_with_port_stripped);
    RUN_TEST(test_host_with_standard_port_stripped);
    RUN_TEST(test_host_leading_whitespace);
    RUN_TEST(test_host_trailing_whitespace);
    RUN_TEST(test_host_uppercase_header);
    RUN_TEST(test_host_mixed_case_header);
    RUN_TEST(test_multiple_headers_before_host);
    RUN_TEST(test_blank_line_stops_search);
    RUN_TEST(test_buf_truncation);
    RUN_TEST(test_lf_only_line_endings);
}
