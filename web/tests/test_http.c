/* Request classification on hand-written request bytes (RFC 9112 §2-5),
 * no socket. The server tests repeat the important cases over a real
 * loopback connection. */
#include <stdlib.h>
#include <string.h>

#include "web_http.h"
#include "wtest.h"

static int cls(const char *req, int *is_head) {
    return web_http_classify(req, strlen(req), is_head);
}

static void test_get_and_head_are_404(void) {
    static const char *const targets[] = {
        "/", "/api/health", "/api/live", "/events", "/index.html",
        "/assets/app.js", "/?q=1", "*", "http://127.0.0.1:8770/",
    };
    for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        char req[256];
        int h = -1;
        snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: x\r\n\r\n",
                 targets[i]);
        WT_EQ(cls(req, &h), 404);
        WT_EQ(h, 0);
        snprintf(req, sizeof(req), "HEAD %s HTTP/1.0\r\n\r\n", targets[i]);
        WT_EQ(cls(req, &h), 404);
        WT_EQ(h, 1);
    }
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
    WT_EQ(cls("GET / HTTP/1.1\nHost: x\n\n", &h), 404);
    WT_EQ(cls("\r\n\r\nGET / HTTP/1.1\r\n\r\n", &h), 404);
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
    WT_EQ(cls("GET / HTTP/1.0\r\n\r\n", &h), 404);
    WT_EQ(cls("GET / HTTP/1.9\r\n\r\n", &h), 404);
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
    WT_EQ(web_http_classify(at, WEB_HDR_MAX, &h), 404);
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

void run_http_tests(void) {
    WT_RUN(test_get_and_head_are_404);
    WT_RUN(test_every_other_method_is_405);
    WT_RUN(test_incomplete_needs_more);
    WT_RUN(test_split_across_reads);
    WT_RUN(test_bare_lf_and_leading_empty_lines);
    WT_RUN(test_malformed_is_400);
    WT_RUN(test_version);
    WT_RUN(test_header_cap_is_431);
    WT_RUN(test_responses);
}
