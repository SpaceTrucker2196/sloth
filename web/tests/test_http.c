/* Request parsing on hand-written request bytes (RFC 9112 §2-5,
 * RFC 9110 §13.1.2), no socket. The server tests repeat the important cases over a real
 * loopback connection. */
#include <stdlib.h>
#include <string.h>

#include "web_http.h"
#include "wtest.h"

static int cls(const char *req, int *is_head) {
    return web_http_classify(req, strlen(req), is_head);
}

/* Every well-formed GET or HEAD reaches the router, whatever its
 * target; web_routes.c decides between a route and 404. */
static void test_get_and_head_are_routed(void) {
    static const char *const targets[] = {
        "/", "/api/health", "/api/live", "/events", "/index.html",
        "/assets/app.js", "/?q=1", "*", "http://127.0.0.1:8770/",
    };
    for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        char req[256];
        int h = -1;
        snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: x\r\n\r\n",
                 targets[i]);
        WT_EQ(cls(req, &h), WEB_HTTP_ROUTE);
        WT_EQ(h, 0);
        snprintf(req, sizeof(req), "HEAD %s HTTP/1.0\r\n\r\n", targets[i]);
        WT_EQ(cls(req, &h), WEB_HTTP_ROUTE);
        WT_EQ(h, 1);
    }
}

static int parse(const char *req, web_req_t *rq) {
    return web_http_parse(req, strlen(req), rq);
}

/* RFC 9112 §3.2: origin-form and absolute-form targets route by path;
 * the query is not part of the route. */
static void test_path_kept_without_query(void) {
    static const struct { const char *target, *path; } cases[] = {
        { "/",                                "/" },
        { "/api/health",                      "/api/health" },
        { "/api/health?x=1&y=2",              "/api/health" },
        { "/?",                               "/" },
        { "/events?types=dns",                "/events" },
        { "http://127.0.0.1:8770/api/health", "/api/health" },
        { "HTTP://127.0.0.1:8770",            "/" },
        { "http://[::1]:8770/?q",             "/" },
        { "*",                                "*" },
        { "/API/HEALTH",                      "/API/HEALTH" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char req[256];
        web_req_t rq;
        snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\n\r\n",
                 cases[i].target);
        WT_EQ(parse(req, &rq), WEB_HTTP_ROUTE);
        if (strcmp(rq.path, cases[i].path))
            fprintf(stderr, "    %s -> \"%s\"\n", cases[i].target, rq.path);
        WT_ASSERT(!strcmp(rq.path, cases[i].path));
        WT_EQ(rq.path_long, 0);
    }

    /* A path that does not fit is flagged, never truncated into a
     * shorter path that might match a route. */
    char *req = malloc(WEB_PATH_MAX + 64);
    memcpy(req, "GET /", 5);
    memset(req + 5, 'a', WEB_PATH_MAX);
    strcpy(req + 5 + WEB_PATH_MAX, " HTTP/1.1\r\n\r\n");
    web_req_t rq;
    WT_EQ(parse(req, &rq), WEB_HTTP_ROUTE);
    WT_EQ(rq.path_long, 1);
    WT_EQ(rq.path[0], '\0');
    free(req);
}

static void test_if_none_match_collected(void) {
    web_req_t rq;
    WT_EQ(parse("GET / HTTP/1.1\r\nHost: x\r\n\r\n", &rq), WEB_HTTP_ROUTE);
    WT_EQ(rq.inm_present, 0);

    /* Field names are case-insensitive (RFC 9110 §5.1); OWS goes. */
    WT_EQ(parse("GET / HTTP/1.1\r\nif-NONE-match:  \"abc\" \t\r\n\r\n", &rq),
          WEB_HTTP_ROUTE);
    WT_EQ(rq.inm_present, 1);
    WT_ASSERT(!strcmp(rq.inm, "\"abc\""));

    /* Two lines are one list (RFC 9110 §5.3). */
    WT_EQ(parse("GET / HTTP/1.1\r\nIf-None-Match: \"a\"\r\n"
                "X: y\r\nIf-None-Match: W/\"b\"\r\n\r\n", &rq),
          WEB_HTTP_ROUTE);
    WT_ASSERT(!strcmp(rq.inm, "\"a\", W/\"b\""));

    /* A similar-looking field is not it. */
    WT_EQ(parse("GET / HTTP/1.1\r\nIf-None-Matches: \"a\"\r\n\r\n", &rq),
          WEB_HTTP_ROUTE);
    WT_EQ(rq.inm_present, 0);

    /* Too long to keep: present, flagged, and the router ignores it. */
    char big[WEB_INM_MAX + 128];
    int n = snprintf(big, sizeof(big), "GET / HTTP/1.1\r\nIf-None-Match: ");
    memset(big + n, 'x', WEB_INM_MAX);
    strcpy(big + n + WEB_INM_MAX, "\r\n\r\n");
    WT_EQ(parse(big, &rq), WEB_HTTP_ROUTE);
    WT_EQ(rq.inm_present, 1);
    WT_EQ(rq.inm_long, 1);
}

/* RFC 9110 §13.1.2: If-None-Match uses the weak comparison. */
static void test_inm_matching(void) {
    const char *et = "\"abc\"";
    WT_EQ(web_http_inm_matches("\"abc\"", et), 1);
    WT_EQ(web_http_inm_matches("W/\"abc\"", et), 1);
    WT_EQ(web_http_inm_matches("*", et), 1);
    WT_EQ(web_http_inm_matches("\"x\", \"abc\"", et), 1);
    WT_EQ(web_http_inm_matches(" \"x\" ,W/\"abc\" ", et), 1);
    WT_EQ(web_http_inm_matches("\"abcd\"", et), 0);
    WT_EQ(web_http_inm_matches("\"ab\"", et), 0);
    WT_EQ(web_http_inm_matches("abc", et), 0);
    WT_EQ(web_http_inm_matches("w/\"abc\"", et), 0);   /* W/ is case-sensitive */
    WT_EQ(web_http_inm_matches("", et), 0);
    WT_EQ(web_http_inm_matches(",,", et), 0);
    WT_EQ(web_http_inm_matches("\"x\", *", et), 1);
}

static void test_every_other_method_is_405(void) {
    static const char *const methods[] = {
        "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT",
        "PROPFIND", "get", "Head", "GETX", "X",
    };
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        char req[256];
        int h = -1;
        snprintf(req, sizeof(req),
                 "%s / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
                 methods[i]);
        int st = cls(req, &h);
        if (st != 405) fprintf(stderr, "    %s -> %d\n", methods[i], st);
        WT_EQ(st, 405);
        WT_EQ(h, 0);
    }
}

static void test_incomplete_needs_more(void) {
    static const char *const partial[] = {
        "", "G", "GET", "GET / HTTP/1.1", "GET / HTTP/1.1\r",
        "GET / HTTP/1.1\r\n", "GET / HTTP/1.1\r\nHost: x\r\n",
        "GET / HTTP/1.1\r\nHost: x\r\n\r", "\r\n\r\n",
    };
    for (size_t i = 0; i < sizeof(partial) / sizeof(partial[0]); i++) {
        int h;
        WT_EQ(cls(partial[i], &h), 0);
    }
}

/* Feed a request one byte at a time: the answer arrives exactly when the
 * empty line does, never before. */
static void test_split_across_reads(void) {
    const char *req = "PUT /x HTTP/1.1\r\nHost: x\r\nA: b\r\n\r\n";
    size_t n = strlen(req);
    int h;
    for (size_t i = 1; i < n; i++) WT_EQ(web_http_classify(req, i, &h), 0);
    WT_EQ(web_http_classify(req, n, &h), 405);
}

static void test_bare_lf_and_leading_empty_lines(void) {
    int h;
    WT_EQ(cls("GET / HTTP/1.1\nHost: x\n\n", &h), WEB_HTTP_ROUTE);
    WT_EQ(cls("\r\n\r\nGET / HTTP/1.1\r\n\r\n", &h), WEB_HTTP_ROUTE);
}

static void test_malformed_is_400(void) {
    static const char *const bad[] = {
        "GET\r\n\r\n",
        "GET /\r\n\r\n",
        "GET  / HTTP/1.1\r\n\r\n",          /* two spaces */
        "GET / HTTP/1.1 \r\n\r\n",
        "GET / http/1.1\r\n\r\n",
        "GET / HTTP/11\r\n\r\n",
        "GET / HTTP/1.10\r\n\r\n",
        " GET / HTTP/1.1\r\n\r\n",
        "GET /a\rb HTTP/1.1\r\n\r\n",       /* bare CR */
        "GET / HTTP/1.1\r\nHost x\r\n\r\n", /* no colon */
        "GET / HTTP/1.1\r\nHost : x\r\n\r\n",
        "GET / HTTP/1.1\r\n: x\r\n\r\n",
        "GET / HTTP/1.1\r\nA: b\r\n c\r\n\r\n",  /* obs-fold */
        "GET / HTTP/1.1\r\nA: b\rc\r\n\r\n",
        "G(T / HTTP/1.1\r\n\r\n",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int h = -1;
        int st = cls(bad[i], &h);
        if (st != 400) fprintf(stderr, "    case %zu -> %d\n", i, st);
        WT_EQ(st, 400);
    }
    /* A NUL in the request line: strlen() would stop at it, so pass the
     * length explicitly. */
    static const char nul[] = "GET /\0 HTTP/1.1\r\n\r\n";
    int h;
    WT_EQ(web_http_classify(nul, sizeof(nul) - 1, &h), 400);
    /* A bad header after a HEAD line drops the HEAD flag with it. */
    WT_EQ(cls("HEAD / HTTP/1.1\r\nbad\r\n\r\n", &h), 400);
    WT_EQ(h, 0);
}

static void test_version(void) {
    int h;
    WT_EQ(cls("GET / HTTP/2.0\r\n\r\n", &h), 505);
    WT_EQ(cls("GET / HTTP/0.9\r\n\r\n", &h), 505);
    WT_EQ(cls("GET / HTTP/1.0\r\n\r\n", &h), WEB_HTTP_ROUTE);
    WT_EQ(cls("GET / HTTP/1.9\r\n\r\n", &h), WEB_HTTP_ROUTE);
}

/* Build "GET / HTTP/1.1\r\nX: aaaa...\r\n\r\n" of exactly `total` bytes. */
static char *sized_request(size_t total) {
    static const char head[] = "GET / HTTP/1.1\r\nX: ";
    static const char tail[] = "\r\n\r\n";
    size_t hl = sizeof(head) - 1, tl = sizeof(tail) - 1;
    char *r = malloc(total + 1);
    memcpy(r, head, hl);
    memset(r + hl, 'a', total - hl - tl);
    memcpy(r + total - tl, tail, tl);
    r[total] = '\0';
    return r;
}

static void test_header_cap_is_431(void) {
    int h;
    /* Exactly at the cap: the block fits, so it is answered normally. */
    char *at = sized_request(WEB_HDR_MAX);
    WT_EQ(web_http_classify(at, WEB_HDR_MAX, &h), WEB_HTTP_ROUTE);
    free(at);

    /* One byte over: the empty line ends past the cap. Seen red with
     * the cap comparison in web_http_classify() moved one byte later. */
    char *over = sized_request(WEB_HDR_MAX + 1);
    WT_EQ(web_http_classify(over, WEB_HDR_MAX + 1, &h), 431);
    /* What the server actually holds of it: the first WEB_HDR_MAX bytes,
     * no terminator yet, buffer full. */
    WT_EQ(web_http_classify(over, WEB_HDR_MAX, &h), 431);
    WT_EQ(web_http_classify(over, WEB_HDR_MAX - 1, &h), 0);
    free(over);

    /* A cap overflow is 431 for every method; the method is not looked
     * at once the block cannot be held. */
    char *post = sized_request(WEB_HDR_MAX + 100);
    memcpy(post, "PUT", 3);
    WT_EQ(web_http_classify(post, WEB_HDR_MAX, &h), 431);
    free(post);
}

static void test_responses(void) {
    char out[1024];
    size_t n = web_http_response(404, 0, out, sizeof(out));
    WT_ASSERT(n > 0);
    WT_HAS(out, "HTTP/1.1 404 Not Found\r\n");
    WT_HAS(out, "Content-Length: 10\r\n");
    WT_HAS(out, "Connection: close\r\n");
    WT_HAS(out, "\r\n\r\nnot found\n");
    WT_LACKS(out, "Allow:");
    WT_ASSERT(n >= 10 && !memcmp(out + n - 10, "not found\n", 10));

    /* HEAD: identical headers, Content-Length included, no body. Seen
     * red with the is_head argument ignored in web_http_response(). */
    char head[1024];
    size_t hn = web_http_response(404, 1, head, sizeof(head));
    WT_EQ(hn, n - 10);
    WT_ASSERT(!memcmp(head, out, hn));
    WT_LACKS(head, "not found\n");

    n = web_http_response(405, 0, out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 405 Method Not Allowed\r\n");
    WT_HAS(out, "Allow: GET, HEAD\r\n");
    n = web_http_response(431, 0, out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 431 Request Header Fields Too Large\r\n");
    n = web_http_response(408, 0, out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 408 Request Timeout\r\n");
    n = web_http_response(400, 0, out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 400 Bad Request\r\n");
    n = web_http_response(505, 0, out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 505 HTTP Version Not Supported\r\n");

    /* Too small a buffer is reported, not truncated. */
    WT_EQ(web_http_response(404, 0, out, 16), 0);
    (void)n;
}

/* RFC 9110 §7.2: the Host value is kept trimmed, every Host line is
 * counted (the router 400s anything but one), an oversize value is
 * flagged rather than truncated, and an absolute-form target's
 * authority is kept separately. */
static void test_host_collected(void) {
    web_req_t rq;
    WT_EQ(parse("GET / HTTP/1.1\r\nhOsT: \t 127.0.0.1:8770 \r\n\r\n", &rq),
          WEB_HTTP_ROUTE);
    WT_EQ(rq.host_count, 1);
    WT_ASSERT(!strcmp(rq.host, "127.0.0.1:8770"));
    WT_EQ(rq.target_abs, 0);

    WT_EQ(parse("GET / HTTP/1.1\r\n\r\n", &rq), WEB_HTTP_ROUTE);
    WT_EQ(rq.host_count, 0);

    WT_EQ(parse("GET / HTTP/1.1\r\nHost: localhost\r\n"
                "Host: attacker.example\r\n\r\n", &rq), WEB_HTTP_ROUTE);
    WT_EQ(rq.host_count, 2);
    WT_ASSERT(!strcmp(rq.host, "localhost"));

    /* Not a Host line, only a name that starts like one. */
    WT_EQ(parse("GET / HTTP/1.1\r\nHostname: x\r\nX-Host: y\r\n\r\n", &rq),
          WEB_HTTP_ROUTE);
    WT_EQ(rq.host_count, 0);

    WT_EQ(parse("GET http://attacker.example:8770/api/health HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n\r\n", &rq), WEB_HTTP_ROUTE);
    WT_EQ(rq.target_abs, 1);
    WT_ASSERT(!strcmp(rq.target_host, "attacker.example:8770"));
    WT_ASSERT(!strcmp(rq.path, "/api/health"));

    char *req = malloc(WEB_HOST_MAX + 64);
    memcpy(req, "GET / HTTP/1.1\r\nHost: ", 22);
    memset(req + 22, 'a', WEB_HOST_MAX);
    strcpy(req + 22 + WEB_HOST_MAX, "\r\n\r\n");
    WT_EQ(parse(req, &rq), WEB_HTTP_ROUTE);
    WT_EQ(rq.host_count, 1);
    WT_EQ(rq.host_long, 1);
    WT_EQ(rq.host[0], '\0');
    free(req);

    /* A writing method still stops at 405 whatever its Host says. */
    WT_EQ(parse("POST / HTTP/1.1\r\nHost: attacker.example\r\n\r\n", &rq),
          405);
}

static void test_host_ok(void) {
    static const char *const ok[] = {
        "127.0.0.1", "127.0.0.1:8770", "127.0.0.1:", "localhost",
        "LOCALHOST:8770", "[::1]", "[::1]:8770", "[::1]:", "192.168.1.5:8770",
        "0.0.0.0:8770", "[fe80::1]:65535",
    };
    static const char *const bad[] = {
        "", "x", "attacker.example", "attacker.example:8770",
        "127.0.0.1.attacker.example", "localhost.attacker.example",
        "evil.localhost", "localhost.", "::1", "[::1", "[]", "[::1]x",
        "127.0.0.1:65536", "127.0.0.1:123456", "127.0.0.1:80a",
        "127.1", "0x7f.0.0.1", "127.0.0.1:8770:1", "user@127.0.0.1",
        "[127.0.0.1]", "2130706433",
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        if (!web_http_host_ok(ok[i])) fprintf(stderr, "    refused %s\n", ok[i]);
        WT_ASSERT(web_http_host_ok(ok[i]));
    }
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (web_http_host_ok(bad[i])) fprintf(stderr, "    allowed %s\n", bad[i]);
        WT_ASSERT(!web_http_host_ok(bad[i]));
    }
}

void run_http_tests(void) {
    WT_RUN(test_host_collected);
    WT_RUN(test_host_ok);
    WT_RUN(test_get_and_head_are_routed);
    WT_RUN(test_path_kept_without_query);
    WT_RUN(test_if_none_match_collected);
    WT_RUN(test_inm_matching);
    WT_RUN(test_every_other_method_is_405);
    WT_RUN(test_incomplete_needs_more);
    WT_RUN(test_split_across_reads);
    WT_RUN(test_bare_lf_and_leading_empty_lines);
    WT_RUN(test_malformed_is_400);
    WT_RUN(test_version);
    WT_RUN(test_header_cap_is_431);
    WT_RUN(test_responses);
}
