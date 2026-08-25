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

/* Boundary at sel == n + empty-log clamp tests. */
static void test_snapshot_clamps_sel_at_boundary_and_empty(void) {
    http_log_clear();
    http_log_entry_t e = make_entry("1.1.1.1", "GET", "x.com", "/");
    http_log_record(&e);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.http_log_sel = 1;
    http_log_snapshot(&s);
    ASSERT_EQ(s.http_log_sel, 0);

    http_log_clear();
    memset(&s, 0, sizeof(s));
    s.http_log_sel = 5;
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

/* ── JA4H tests ─────────────────────────────────────────────
 *
 * FoxIO JA4H format: a(10) _ b(12) _ c(12) _ d(12) = 49 chars.
 * a = method(2) + version(2) + cookie-flag(1) + referer-flag(1)
 *   + numheaders(2) + primary-language(2). */

static int is_lower_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

static void test_ja4h_shape_get_no_cookies(void) {
    const char *req =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: curl/8\r\n"
        "\r\n";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse(u8(req), (int)strlen(req), "1.1.1.1", &e), 1);
    ASSERT_EQ((int)strlen(e.ja4h), 49);
    /* method="ge", version="11", no cookie, no referer, 2 headers,
     * no accept-language. */
    ASSERT_EQ((int)e.ja4h[0], (int)'g');
    ASSERT_EQ((int)e.ja4h[1], (int)'e');
    ASSERT_EQ((int)e.ja4h[2], (int)'1');
    ASSERT_EQ((int)e.ja4h[3], (int)'1');
    ASSERT_EQ((int)e.ja4h[4], (int)'n');   /* no cookie */
    ASSERT_EQ((int)e.ja4h[5], (int)'n');   /* no referer */
    ASSERT_EQ((int)e.ja4h[6], (int)'0');   /* numheaders 02 */
    ASSERT_EQ((int)e.ja4h[7], (int)'2');
    ASSERT_EQ((int)e.ja4h[8], (int)'0');   /* lang "00" */
    ASSERT_EQ((int)e.ja4h[9], (int)'0');
    ASSERT_EQ((int)e.ja4h[10], (int)'_');
    ASSERT_EQ((int)e.ja4h[23], (int)'_');
    ASSERT_EQ((int)e.ja4h[36], (int)'_');
    /* Sections c and d are 000000000000 when there are no cookies. */
    for (int i = 24; i < 36; i++) ASSERT_EQ((int)e.ja4h[i], (int)'0');
    for (int i = 37; i < 49; i++) ASSERT_EQ((int)e.ja4h[i], (int)'0');
}

static void test_ja4h_flags_cookie_and_referer(void) {
    const char *req =
        "POST /submit HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Cookie: sid=abc\r\n"
        "Referer: https://example.com/form\r\n"
        "User-Agent: curl/8\r\n"
        "\r\n";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse(u8(req), (int)strlen(req), "1.1.1.1", &e), 1);
    /* method "po", cookie flag 'c', referer flag 'r'. Cookie and
     * Referer excluded from numheaders → Host + UA = 2. */
    ASSERT_EQ((int)e.ja4h[0], (int)'p');
    ASSERT_EQ((int)e.ja4h[1], (int)'o');
    ASSERT_EQ((int)e.ja4h[4], (int)'c');
    ASSERT_EQ((int)e.ja4h[5], (int)'r');
    ASSERT_EQ((int)e.ja4h[6], (int)'0');
    ASSERT_EQ((int)e.ja4h[7], (int)'2');
    /* Sections c and d are non-zero because we have a cookie. */
    ASSERT(strncmp(e.ja4h + 24, "000000000000", 12) != 0);
    ASSERT(strncmp(e.ja4h + 37, "000000000000", 12) != 0);
    /* And they're lowercase hex. */
    for (int i = 24; i < 36; i++) ASSERT(is_lower_hex(e.ja4h[i]));
    for (int i = 37; i < 49; i++) ASSERT(is_lower_hex(e.ja4h[i]));
}

static void test_ja4h_extracts_accept_language(void) {
    const char *req =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "\r\n";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse(u8(req), (int)strlen(req), "1.1.1.1", &e), 1);
    /* Section-a lang chars 8+9 come from first two chars of the
     * first language tag, lowercased. "en" here. */
    ASSERT_EQ((int)e.ja4h[8], (int)'e');
    ASSERT_EQ((int)e.ja4h[9], (int)'n');
}

static void test_ja4h_cookie_hash_stable_across_reorder(void) {
    /* Two requests with the same cookie *names* in different insertion
     * order must produce the same JA4H section c (which sorts by name).
     * Values here are identical to keep section d equal too. */
    const char *req1 =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Cookie: a=1; b=2; c=3\r\n"
        "\r\n";
    const char *req2 =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Cookie: c=3; a=1; b=2\r\n"
        "\r\n";
    http_log_entry_t e1, e2;
    ASSERT_EQ(http_log_parse(u8(req1), (int)strlen(req1), "x", &e1), 1);
    ASSERT_EQ(http_log_parse(u8(req2), (int)strlen(req2), "x", &e2), 1);
    /* Sections c and d span [24..35] and [37..48]. */
    ASSERT(strncmp(e1.ja4h + 24, e2.ja4h + 24, 12) == 0);
    ASSERT(strncmp(e1.ja4h + 37, e2.ja4h + 37, 12) == 0);
}

static void test_ja4h_deterministic(void) {
    const char *req =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: curl/8\r\n"
        "\r\n";
    http_log_entry_t a, b;
    ASSERT_EQ(http_log_parse(u8(req), (int)strlen(req), "x", &a), 1);
    ASSERT_EQ(http_log_parse(u8(req), (int)strlen(req), "y", &b), 1);
    ASSERT_STR(a.ja4h, b.ja4h);
}

/* ── Suite entry point ───────────────────────────────────── */


/* ── HTTP response-side parsing (#71) ────────────────────── */

static int mk_resp(char *buf, int cap, const char *status_line,
                   const char *hdrs, const char *body) {
    int n = snprintf(buf, (size_t)cap, "%s\r\n%s\r\n%s",
                     status_line, hdrs, body ? body : "");
    return n < cap ? n : cap - 1;
}

static void test_response_status_line(void) {
    char b[512];
    int n = mk_resp(b, sizeof(b), "HTTP/1.1 200 OK",
                    "Content-Length: 5\r\n", "hello");
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse_response((const uint8_t *)b, n, "1.2.3.4", &e), 1);
    ASSERT_EQ(e.is_response, 1);
    ASSERT_EQ((int)e.status, 200);
    ASSERT_EQ(e.content_length, 5);
    ASSERT_EQ(e.resp_body_len, 5);
    ASSERT_EQ(memcmp(e.resp_body, "hello", 5), 0);
    ASSERT_EQ(e.body_complete, 1);
}

static void test_requests_are_not_responses(void) {
    /* And more importantly the reverse: a request must not parse as a
     * response, or every GET becomes a status line. */
    const char *req = "GET /x HTTP/1.1\r\nHost: a.example\r\n\r\n";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse_response((const uint8_t *)req,
                                      (int)strlen(req), "1.2.3.4", &e), 0);
}

static void test_continuation_segment_rejected(void) {
    /* A mid-body segment carries no status line. Its first bytes are
     * body data and can look like anything — accepting one would
     * fabricate a status code out of page content. */
    const char *mid = "<html><body>this is the middle of a page</body>";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse_response((const uint8_t *)mid,
                                      (int)strlen(mid), "1.2.3.4", &e), 0);
}

static void test_204_has_no_body_and_is_complete(void) {
    /* Google's connectivity check. A 204 has no body by definition, so
     * it is complete the moment the headers end — and a consumer must
     * be able to tell that from "we did not see the body". */
    char b[256];
    int n = mk_resp(b, sizeof(b), "HTTP/1.1 204 No Content",
                    "Content-Length: 0\r\n", "");
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse_response((const uint8_t *)b, n, "1.2.3.4", &e), 1);
    ASSERT_EQ((int)e.status, 204);
    ASSERT_EQ(e.resp_body_len, 0);
    ASSERT_EQ(e.body_complete, 1);
}

static void test_truncated_body_is_incomplete_not_different(void) {
    /* **The distinction this whole parser exists to make.** sloth does
     * not reassemble TCP, so a body larger than its segment arrives
     * short. A consumer comparing bytes must be able to tell "different"
     * from "incomplete" — a partial body that happens to differ from an
     * expected value is not evidence of anything. */
    char b[512];
    int n = mk_resp(b, sizeof(b), "HTTP/1.1 200 OK",
                    "Content-Length: 5000\r\n", "only the start");
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse_response((const uint8_t *)b, n, "1.2.3.4", &e), 1);
    ASSERT_EQ(e.content_length, 5000);
    ASSERT(e.resp_body_len > 0);
    ASSERT_EQ(e.body_complete, 0);
}

static void test_body_longer_than_the_bound_is_incomplete(void) {
    char b[2048];
    char body[1200];
    memset(body, 'A', sizeof(body) - 1);
    body[sizeof(body) - 1] = '\0';
    char hdrs[64];
    snprintf(hdrs, sizeof(hdrs), "Content-Length: %d\r\n",
             (int)strlen(body));
    int n = mk_resp(b, sizeof(b), "HTTP/1.1 200 OK", hdrs, body);
    http_log_entry_t e;
    http_log_parse_response((const uint8_t *)b, n, "1.2.3.4", &e);
    ASSERT_EQ(e.resp_body_len, HTTP_RESP_BODY_MAX);
    ASSERT_EQ(e.body_complete, 0);
}

static void test_chunked_is_never_complete(void) {
    /* The body is interleaved with chunk-size lines and this does not
     * decode them. Calling the raw bytes "the body" would produce a
     * mismatch on a response that is actually correct. */
    char b[512];
    int n = mk_resp(b, sizeof(b), "HTTP/1.1 200 OK",
                    "Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\n\r\n");
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse_response((const uint8_t *)b, n, "1.2.3.4", &e), 1);
    ASSERT_EQ(e.chunked, 1);
    ASSERT_EQ(e.body_complete, 0);

    /* The case the chunked check actually earns its keep on, and the
     * one an attacker would reach for: chunked *and* a Content-Length
     * that matches the raw bytes on the wire. Every other route to
     * body_complete=0 is closed, so without the chunked branch this
     * response is declared complete and its chunk-size lines get
     * compared against a sentinel as though they were the body. */
    const char *raw = "5\r\nhello\r\n0\r\n\r\n";
    char hdrs[96];
    snprintf(hdrs, sizeof(hdrs),
             "Transfer-Encoding: chunked\r\nContent-Length: %d\r\n",
             (int)strlen(raw));
    n = mk_resp(b, sizeof(b), "HTTP/1.1 200 OK", hdrs, raw);
    ASSERT_EQ(http_log_parse_response((const uint8_t *)b, n, "1.2.3.4", &e), 1);
    ASSERT_EQ(e.chunked, 1);
    ASSERT_EQ(e.content_length, (int)strlen(raw));
    ASSERT_EQ(e.resp_body_len, (int)strlen(raw));
    ASSERT_EQ(e.body_complete, 0);

    /* And chunked on a 204, which the status shortcut would otherwise
     * call complete. */
    n = mk_resp(b, sizeof(b), "HTTP/1.1 204 No Content",
                "Transfer-Encoding: chunked\r\n", "");
    ASSERT_EQ(http_log_parse_response((const uint8_t *)b, n, "1.2.3.4", &e), 1);
    ASSERT_EQ(e.body_complete, 0);
}

static void test_no_content_length_is_incomplete(void) {
    /* Body runs to connection close; we cannot know we have all of it. */
    char b[256];
    int n = mk_resp(b, sizeof(b), "HTTP/1.1 200 OK",
                    "Content-Type: text/html\r\n", "some bytes");
    http_log_entry_t e;
    http_log_parse_response((const uint8_t *)b, n, "1.2.3.4", &e);
    ASSERT_EQ(e.content_length, -1);
    ASSERT_EQ(e.body_complete, 0);
}

static void test_headers_only_segment(void) {
    /* No blank line: the headers ran past this segment. */
    const char *h = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nServer: x";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse_response((const uint8_t *)h,
                                      (int)strlen(h), "1.2.3.4", &e), 1);
    ASSERT_EQ(e.resp_body_len, 0);
    ASSERT_EQ(e.body_complete, 0);
}

static void test_bare_lf_header_terminator(void) {
    /* A rogue portal has no reason to be well-behaved, and bare-LF
     * terminators exist in the wild. */
    const char *r = "HTTP/1.1 200 OK\nContent-Length: 2\n\nhi";
    http_log_entry_t e;
    ASSERT_EQ(http_log_parse_response((const uint8_t *)r,
                                      (int)strlen(r), "1.2.3.4", &e), 1);
    ASSERT_EQ(e.resp_body_len, 2);
    ASSERT_EQ(e.body_complete, 1);
}

static void test_absurd_content_length_treated_as_absent(void) {
    char b[256];
    int n = mk_resp(b, sizeof(b), "HTTP/1.1 200 OK",
                    "Content-Length: 99999999999\r\n", "x");
    http_log_entry_t e;
    http_log_parse_response((const uint8_t *)b, n, "1.2.3.4", &e);
    ASSERT_EQ(e.content_length, -1);
    ASSERT_EQ(e.body_complete, 0);
}

static void test_malformed_status_lines_rejected(void) {
    http_log_entry_t e;
    const char *bad[] = {
        "HTTP/2.0 200 OK\r\n\r\n",       /* not 1.x */
        "HTTP/1.1 2OO OK\r\n\r\n",       /* letters, not digits */
        "HTTP/1.1200 OK\r\n\r\n",        /* no space */
        "HTTP/1.",                        /* truncated */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        ASSERT_EQ(http_log_parse_response((const uint8_t *)bad[i],
                                          (int)strlen(bad[i]),
                                          "1.2.3.4", &e), 0);
}

/* ── pairing ── */

static void mk_req(http_log_entry_t *e, const char *host, const char *path) {
    memset(e, 0, sizeof(*e));
    snprintf(e->src, sizeof(e->src), "10.0.0.5");
    snprintf(e->dst, sizeof(e->dst), "17.253.1.1");
    e->src_port = 51000;
    e->dst_port = 80;
    snprintf(e->method, sizeof(e->method), "GET");
    snprintf(e->host, sizeof(e->host), "%s", host);
    snprintf(e->path, sizeof(e->path), "%s", path);
    e->ts = time(NULL);
}

static void mk_resp_entry(http_log_entry_t *e) {
    memset(e, 0, sizeof(*e));
    e->is_response = 1;
    snprintf(e->src, sizeof(e->src), "17.253.1.1");
    snprintf(e->dst, sizeof(e->dst), "10.0.0.5");
    e->src_port = 80;
    e->dst_port = 51000;
}

static void test_response_pairs_with_its_request(void) {
    http_log_clear();
    http_log_entry_t req, resp;
    mk_req(&req, "captive.apple.com", "/hotspot-detect.html");
    http_log_record(&req);
    mk_resp_entry(&resp);
    ASSERT_EQ(http_log_pair_response(&resp), 1);
    ASSERT_STR(resp.host, "captive.apple.com");
    ASSERT_STR(resp.path, "/hotspot-detect.html");
    http_log_clear();
}

static void test_unmatched_response_is_unpaired(void) {
    /* A response on a flow we never saw a request for. Attaching it to
     * whatever request happened to be around would attribute it to the
     * wrong URL, which for a sentinel comparison is worse than nothing. */
    http_log_clear();
    http_log_entry_t resp;
    mk_resp_entry(&resp);
    resp.dst_port = 51999;              /* a different flow */
    ASSERT_EQ(http_log_pair_response(&resp), 0);
    ASSERT_EQ((int)resp.host[0], 0);
    http_log_clear();
}

static void test_pipelining_is_left_unpaired(void) {
    /* Two requests in flight: which one the next response answers stops
     * being knowable, so neither is claimed. */
    http_log_clear();
    http_log_entry_t a, b, resp;
    mk_req(&a, "one.example", "/a");
    http_log_record(&a);
    mk_req(&b, "two.example", "/b");
    http_log_record(&b);
    mk_resp_entry(&resp);
    ASSERT_EQ(http_log_pair_response(&resp), 0);
    ASSERT_EQ((int)resp.host[0], 0);
    http_log_clear();
}

static void test_pairing_consumes_the_request(void) {
    /* A second response on the same flow must not re-use the first
     * request — keep-alive means the next answer is to something else. */
    http_log_clear();
    http_log_entry_t req, r1, r2;
    mk_req(&req, "one.example", "/a");
    http_log_record(&req);
    mk_resp_entry(&r1);
    ASSERT_EQ(http_log_pair_response(&r1), 1);
    mk_resp_entry(&r2);
    ASSERT_EQ(http_log_pair_response(&r2), 0);
    http_log_clear();
}

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
    RUN_TEST(test_ja4h_shape_get_no_cookies);
    RUN_TEST(test_ja4h_flags_cookie_and_referer);
    RUN_TEST(test_ja4h_extracts_accept_language);
    RUN_TEST(test_ja4h_cookie_hash_stable_across_reorder);
    RUN_TEST(test_ja4h_deterministic);
    RUN_TEST(test_record_and_snapshot);
    RUN_TEST(test_snapshot_newest_first);
    RUN_TEST(test_clear_empties_log);
    RUN_TEST(test_snapshot_clamps_sel);
    RUN_TEST(test_snapshot_clamps_sel_at_boundary_and_empty);
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_populated);
    RUN_TEST(test_view_key_nav);
    RUN_TEST(test_view_key_clear);
    TEST_SUITE("HTTP response parsing (#71)");
    RUN_TEST(test_response_status_line);
    RUN_TEST(test_requests_are_not_responses);
    RUN_TEST(test_continuation_segment_rejected);
    RUN_TEST(test_204_has_no_body_and_is_complete);
    RUN_TEST(test_truncated_body_is_incomplete_not_different);
    RUN_TEST(test_body_longer_than_the_bound_is_incomplete);
    RUN_TEST(test_chunked_is_never_complete);
    RUN_TEST(test_no_content_length_is_incomplete);
    RUN_TEST(test_headers_only_segment);
    RUN_TEST(test_bare_lf_header_terminator);
    RUN_TEST(test_absurd_content_length_treated_as_absent);
    RUN_TEST(test_malformed_status_lines_rejected);

    TEST_SUITE("HTTP request/response pairing (#71)");
    RUN_TEST(test_response_pairs_with_its_request);
    RUN_TEST(test_unmatched_response_is_unpaired);
    RUN_TEST(test_pipelining_is_left_unpaired);
    RUN_TEST(test_pairing_consumes_the_request);
}
