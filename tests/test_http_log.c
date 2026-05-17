#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "http_log.h"
#include "views/http.h"

static const uint8_t *u8(const char *s) { return (const uint8_t *)s; }

/* ── http_log_parse tests ────────────────────────────────── */

static void test_parse_get(void) {
    const char *req =
        "GET /index.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    http_log_entry_t e;
    int r = http_log_parse(u8(req), (int)strlen(req), "192.168.1.5", &e);
    ASSERT_EQ(r, 1);
    ASSERT_STR(e.method, "GET");
    ASSERT_STR(e.host,   "example.com");
    ASSERT_STR(e.path,   "/index.html");
    ASSERT_STR(e.src,    "192.168.1.5");
}

static void test_parse_post(void) {
    const char *req =
        "POST /api/login HTTP/1.1\r\n"
        "Host: auth.example.com\r\n"
        "Content-Type: application/json\r\n"
        "\r\n";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse(u8(req), (int)strlen(req), "10.0.0.1", &e), 1);
    ASSERT_STR(e.method, "POST");
    ASSERT_STR(e.host,   "auth.example.com");
    ASSERT_STR(e.path,   "/api/login");
}

static void test_parse_host_strips_port(void) {
    const char *req =
        "GET /path HTTP/1.1\r\n"
        "Host: myserver.local:8080\r\n"
        "\r\n";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse(u8(req), (int)strlen(req), "127.0.0.1", &e), 1);
    ASSERT_STR(e.host, "myserver.local");
}

static void test_parse_put(void) {
    const char *req =
        "PUT /resource/42 HTTP/1.1\r\n"
        "Host: api.test.com\r\n"
        "\r\n";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse(u8(req), (int)strlen(req), "10.1.2.3", &e), 1);
    ASSERT_STR(e.method, "PUT");
    ASSERT_STR(e.path,   "/resource/42");
}

static void test_parse_rejects_response(void) {
    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse(u8(resp), (int)strlen(resp), "1.2.3.4", &e), 0);
}

static void test_parse_rejects_short(void) {
    const char *s = "GET /";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse(u8(s), (int)strlen(s), "1.2.3.4", &e), 0);
}

static void test_parse_rejects_junk(void) {
    const char *s = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse(u8(s), 16, "1.2.3.4", &e), 0);
}

static void test_parse_path_truncated(void) {
    /* path longer than 127 chars should be truncated, not overflow */
    char req[512];
    char longpath[200];
    memset(longpath, 'x', 180); longpath[180] = '\0';
    snprintf(req, sizeof(req),
             "GET /%s HTTP/1.1\r\nHost: h.com\r\n\r\n", longpath);
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse(u8(req), (int)strlen(req), "1.2.3.4", &e), 1);
    ASSERT_EQ((int)strlen(e.path), 127);
}

static void test_parse_no_host_header(void) {
    /* HTTP/1.0 request without Host header — still valid */
    const char *req = "GET /page.html HTTP/1.0\r\n\r\n";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse(u8(req), (int)strlen(req), "1.2.3.4", &e), 1);
    ASSERT_STR(e.method, "GET");
    ASSERT_STR(e.path,   "/page.html");
    /* host is empty but parse succeeds */
}

static void test_parse_head_method(void) {
    const char *req = "HEAD / HTTP/1.1\r\nHost: check.io\r\n\r\n";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse(u8(req), (int)strlen(req), "1.2.3.4", &e), 1);
    ASSERT_STR(e.method, "HEAD");
}

/* ── http_log_record / http_log_snapshot tests ───────────── */

static http_log_entry_t make_entry(const char *src, const char *method,
                                   const char *host, const char *path)
{
    http_log_entry_t e;
    memset(&e, 0, sizeof(e));
    strncpy(e.src,    src,    sizeof(e.src)    - 1);
    strncpy(e.method, method, sizeof(e.method) - 1);
    strncpy(e.host,   host,   sizeof(e.host)   - 1);
    strncpy(e.path,   path,   sizeof(e.path)   - 1);
    e.ts = 1000;
    return e;
}

static void test_record_and_snapshot(void) {
    http_log_clear();
    http_log_entry_t e = make_entry("10.0.0.1", "GET", "example.com", "/");
    http_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    http_log_snapshot(&s);

    ASSERT_EQ(s.http_log_count, 1);
    ASSERT_STR(s.http_log[0].method, "GET");
    ASSERT_STR(s.http_log[0].host,   "example.com");
}

static void test_snapshot_newest_first(void) {
    http_log_clear();
    http_log_entry_t a = make_entry("1.1.1.1", "GET",  "first.com",  "/1");
    http_log_entry_t b = make_entry("2.2.2.2", "POST", "second.com", "/2");
    http_log_record(&a);
    http_log_record(&b);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    http_log_snapshot(&s);

    ASSERT_EQ(s.http_log_count, 2);
    /* newest (b) at index 0 */
    ASSERT_STR(s.http_log[0].host, "second.com");
    ASSERT_STR(s.http_log[1].host, "first.com");
}

static void test_clear_empties_log(void) {
    http_log_record(&(http_log_entry_t){0});
    http_log_clear();

    sloth_state_t s; memset(&s, 0, sizeof(s));
    http_log_snapshot(&s);

    ASSERT_EQ(s.http_log_count, 0);
}

static void test_snapshot_clamps_sel(void) {
    http_log_clear();
    http_log_entry_t e = make_entry("1.1.1.1", "GET", "x.com", "/");
    http_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.http_log_sel = 99;
    http_log_snapshot(&s);

    ASSERT_EQ(s.http_log_sel, 0);
}

/* ── view_http_draw smoke tests ──────────────────────────── */

static void test_view_draw_empty(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_http_draw(&s);
    ASSERT(1);
}

static void test_view_draw_populated(void) {
    http_log_clear();
    http_log_entry_t e1 = make_entry("192.168.1.5", "GET",  "api.example.com", "/v1/users");
    http_log_entry_t e2 = make_entry("192.168.1.10","POST", "auth.svc.local",  "/login");
    http_log_record(&e1);
    http_log_record(&e2);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    http_log_snapshot(&s);
    view_http_draw(&s);
    ASSERT(1);
}

/* ── view_http_key tests ─────────────────────────────────── */

static void test_view_key_nav(void) {
    http_log_clear();
    http_log_entry_t a = make_entry("1.1.1.1", "GET",  "a.com", "/");
    http_log_entry_t b = make_entry("2.2.2.2", "POST", "b.com", "/");
    http_log_record(&a);
    http_log_record(&b);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    http_log_snapshot(&s);
    s.http_log_sel = 0;

    view_http_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.http_log_sel, 1);

    view_http_key(&s, SLOTH_KEY_DOWN);  /* at end */
    ASSERT_EQ(s.http_log_sel, 1);

    view_http_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.http_log_sel, 0);

    view_http_key(&s, SLOTH_KEY_UP);    /* at top */
    ASSERT_EQ(s.http_log_sel, 0);
}

static void test_view_key_clear(void) {
    http_log_clear();
    http_log_entry_t e = make_entry("1.1.1.1", "GET", "x.com", "/");
    http_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    http_log_snapshot(&s);
    ASSERT_EQ(s.http_log_count, 1);

    view_http_key(&s, 'c');
    ASSERT_EQ(s.http_log_count, 0);
    ASSERT_EQ(s.http_log_sel,   0);
}

/* ── Suite entry point ───────────────────────────────────── */

void run_http_log_tests(void) {
    TEST_SUITE("http_log");
    RUN_TEST(test_parse_get);
    RUN_TEST(test_parse_post);
    RUN_TEST(test_parse_host_strips_port);
    RUN_TEST(test_parse_put);
    RUN_TEST(test_parse_rejects_response);
    RUN_TEST(test_parse_rejects_short);
    RUN_TEST(test_parse_rejects_junk);
    RUN_TEST(test_parse_path_truncated);
    RUN_TEST(test_parse_no_host_header);
    RUN_TEST(test_parse_head_method);
    RUN_TEST(test_record_and_snapshot);
    RUN_TEST(test_snapshot_newest_first);
    RUN_TEST(test_clear_empties_log);
    RUN_TEST(test_snapshot_clamps_sel);
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_populated);
    RUN_TEST(test_view_key_nav);
    RUN_TEST(test_view_key_clear);
}
