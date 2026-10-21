/* The route table and the embedded page, without a socket
 * (web_routes.c, build/web/web_assets.c). test_server.c repeats the
 * important answers over a real loopback connection. */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "web_assets.h"
#include "web_routes.h"
#include "wtest.h"

static const char *page(void) { return (const char *)web_page; }

static void req(web_req_t *rq, const char *path, int is_head) {
    memset(rq, 0, sizeof(*rq));
    rq->is_head = is_head;
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
}

static void inm(web_req_t *rq, const char *v) {
    rq->inm_present = 1;
    snprintf(rq->inm, sizeof(rq->inm), "%s", v);
}

static const web_health_t H = { 42, 2, 17 };

/* Case-insensitive search over the first len bytes. */
static const char *ci_find(const char *hay, size_t len, const char *needle) {
    size_t n = strlen(needle);
    for (size_t i = 0; i + n <= len; i++) {
        size_t k = 0;
        while (k < n && tolower((unsigned char)hay[i + k]) ==
                        tolower((unsigned char)needle[k]))
            k++;
        if (k == n) return hay + i;
    }
    return NULL;
}

/* ── the page ──────────────────────────────────────────────────────────── */

static void test_page_is_200_with_etag_and_csp(void) {
    web_req_t rq;
    web_resp_t r;
    char out[4096];
    req(&rq, "/", 0);
    WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.kind, WEB_R_ONESHOT);
    WT_EQ(r.status, 200);
    WT_ASSERT(r.body == web_page);
    WT_EQ(r.body_len, web_page_len);
    WT_HAS(out, "HTTP/1.1 200 OK\r\n");
    WT_HAS(out, "Content-Type: text/html; charset=utf-8\r\n");
    char cl[64];
    snprintf(cl, sizeof(cl), "Content-Length: %zu\r\n", web_page_len);
    WT_HAS(out, cl);
    char et[96];
    snprintf(et, sizeof(et), "ETag: %s\r\n", web_page_etag);
    WT_HAS(out, et);
    WT_HAS(out, "Cache-Control: no-cache\r\n");
    WT_HAS(out, web_page_csp);
    WT_HAS(out, "X-Content-Type-Options: nosniff\r\n");
    WT_HAS(out, "Connection: close\r\n");
    WT_ASSERT(r.out_len >= 4 && !memcmp(out + r.out_len - 4, "\r\n\r\n", 4));

    /* HEAD: the same headers, Content-Length included, no body. */
    char head[4096];
    web_resp_t hr;
    req(&rq, "/", 1);
    WT_EQ(web_route(&rq, &H, 1, head, sizeof(head), &hr), 0);
    WT_EQ(hr.status, 200);
    WT_ASSERT(hr.body == NULL);
    WT_EQ(hr.body_len, 0);
    WT_EQ(hr.out_len, r.out_len);
    WT_ASSERT(!memcmp(head, out, r.out_len));
}

static void test_page_304_on_matching_validator(void) {
    char weak[96], listed[160];
    snprintf(weak, sizeof(weak), "W/%s", web_page_etag);
    snprintf(listed, sizeof(listed), "\"old\", %s", web_page_etag);
    const char *match[] = { web_page_etag, weak, listed, "*" };
    for (size_t i = 0; i < sizeof(match) / sizeof(match[0]); i++) {
        for (int is_head = 0; is_head < 2; is_head++) {
            web_req_t rq;
            web_resp_t r;
            char out[4096];
            req(&rq, "/", is_head);
            inm(&rq, match[i]);
            WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
            out[r.out_len] = '\0';
            WT_EQ(r.status, 304);
            WT_ASSERT(r.body == NULL);
            WT_HAS(out, "HTTP/1.1 304 Not Modified\r\n");
            char et[96];
            snprintf(et, sizeof(et), "ETag: %s\r\n", web_page_etag);
            WT_HAS(out, et);
            /* A 304 carries no body and so no length (RFC 9110 §15.4.5).
             * Seen red with a Content-Length line added to the 304
             * template in route_page(). */
            WT_LACKS(out, "Content-Length");
            WT_LACKS(out, "<!doctype");
        }
    }

    /* A different tag, a near miss, and a validator too long to keep
     * all get the page. The last is a "*" flagged inm_long: seen red
     * (304) with the inm_long test removed from route_page(). */
    const char *miss[] = { "\"0000\"", "\"\"", "W/\"x\"" };
    for (size_t i = 0; i < sizeof(miss) / sizeof(miss[0]); i++) {
        web_req_t rq;
        web_resp_t r;
        char out[4096];
        req(&rq, "/", 0);
        inm(&rq, miss[i]);
        WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
        WT_EQ(r.status, 200);
        WT_EQ(r.body_len, web_page_len);
    }
    web_req_t rq;
    web_resp_t r;
    char out[4096];
    req(&rq, "/", 0);
    inm(&rq, "*");
    rq.inm_long = 1;
    WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 200);
}

/* docs/web-ui-spec.md §12, M0 acceptance: no external request of any
 * kind. The page is checked as the bytes the server sends, not as the
 * web/ui/ sources, so an @include cannot smuggle anything past it.
 *
 * Seen red three ways, each turned green again by removing the line: a
 * comment naming "https://example.org/x.js" added to web/ui/app.js, an
 * "@font-face { ... src: url(f.woff2); }" rule added to web/ui/page.css,
 * and a <link rel=stylesheet href=x.css> line added to
 * web/ui/index.html. */
static void test_page_makes_no_external_reference(void) {
    const char *p = page();
    size_t n = web_page_len;
    WT_EQ(strlen(p), n);

    static const char *const banned[] = {
        /* any absolute URL, whatever the case */
        "http://", "https://", "ws://", "wss://", "ftp://",
        /* protocol-relative URLs */
        "\"//", "'//", "(//", "=//",
        /* anything that makes the browser fetch a subresource */
        "<link", "<img", "<iframe", "<object", "<embed", "<base",
        "<source", "<video", "<audio", "<form",
        " src=", " href=", "srcset", "@import", "url(", "@font-face",
        "importScripts", "new Worker", "sendBeacon", "XMLHttpRequest",
        "WebSocket", "<script ", "<style ",
    };
    for (size_t i = 0; i < sizeof(banned) / sizeof(banned[0]); i++) {
        const char *hit = ci_find(p, n, banned[i]);
        if (hit)
            fprintf(stderr, "    page contains \"%s\" at byte %zu\n",
                    banned[i], (size_t)(hit - p));
        WT_ASSERT(hit == NULL);
    }

    /* The two places the page does talk to the server: same-origin,
     * relative paths. */
    WT_HAS(p, "new EventSource(\"/events\")");
    WT_HAS(p, "fetch(\"/api/health\"");
}

/* §8.1 as amended by the 2026-10-21 fonts ruling: the system monospace
 * stack, no font file, no named web font. Seen red with "Fira Code"
 * put back at the head of --font-mono in web/ui/theme.css. */
static void test_font_is_the_system_monospace_stack(void) {
    WT_HAS(page(), "--font-mono: ui-monospace, \"SF Mono\", Menlo, Consolas, "
                   "\"DejaVu Sans Mono\", \"Liberation Mono\", monospace;");
    WT_HAS(page(), "font-family: var(--font-mono);");
    WT_ASSERT(ci_find(page(), web_page_len, "fira") == NULL);
    WT_ASSERT(ci_find(page(), web_page_len, "woff") == NULL);
    WT_ASSERT(ci_find(page(), web_page_len, ".ttf") == NULL);
    WT_ASSERT(ci_find(page(), web_page_len, ".otf") == NULL);
}

/* The value of "--name:" in the token block, whitespace trimmed. */
static int token(const char *name, char *val, size_t sz) {
    char key[64];
    snprintf(key, sizeof(key), "%s:", name);
    const char *t = strstr(page(), key);
    if (!t) return -1;
    t += strlen(key);
    while (*t == ' ') t++;
    size_t n = 0;
    while (t[n] && t[n] != ';' && n + 1 < sz) n++;
    memcpy(val, t, n);
    val[n] = '\0';
    return 0;
}

/* Every token in docs/web-ui-spec.md §8.1, with its value. */
static void test_design_tokens_match_spec(void) {
    static const struct { const char *name, *value; } tok[] = {
        { "--bg", "#0a0a0a" },      { "--panel", "#0f0f0f" },
        { "--rule", "#2a2a2a" },    { "--rule-hi", "#3a3a3a" },
        { "--ink", "#f2f2f2" },     { "--muted", "#8c8c8c" },
        { "--faint", "#5c5c5c" },   { "--signal", "#ff5a00" },
        { "--data", "#00c8ff" },    { "--phosphor", "#00d7af" },
        { "--phosphor-dim", "#00875f" },
        { "--sev-low", "#d7af00" }, { "--sev-warn", "#ff8700" },
        { "--sev-crit", "#ff0000" },
        { "--heat-0", "#626262" },  { "--heat-1", "#d7af00" },
        { "--heat-2", "#ff8700" },  { "--heat-3", "#ff0000" },
        { "--t-dns", "#7fd1ff" },   { "--t-tls", "#b48cff" },
        { "--t-http", "#ffd166" },  { "--t-quic", "#ff9ecb" },
        { "--t-icmp", "#9be564" },  { "--t-arp", "#c0c0c0" },
        { "--t-wifi", "#00d7af" },  { "--t-alert", "#ff5a00" },
        { "--radius", "0" },        { "--gap", "8px" },
    };
    WT_HAS(page(), ":root {");
    for (size_t i = 0; i < sizeof(tok) / sizeof(tok[0]); i++) {
        char v[64];
        int rc = token(tok[i].name, v, sizeof(v));
        WT_EQ(rc, 0);
        if (rc == 0 && strcmp(v, tok[i].value))
            fprintf(stderr, "    %s is \"%s\", spec says %s\n",
                    tok[i].name, v, tok[i].value);
        WT_ASSERT(rc == 0 && !strcmp(v, tok[i].value));
    }
}

/* FIPS 180-4 examples (one block, two blocks) and RFC 4648 §10. */
static void test_sha256_and_base64_vectors(void) {
    static const uint8_t abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    static const uint8_t two[32] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26,
        0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff,
        0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    };
    static const uint8_t empty[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
        0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
        0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    uint8_t d[32];
    web_sha256("abc", 3, d);
    WT_ASSERT(!memcmp(d, abc, 32));
    static const char m2[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    web_sha256(m2, sizeof(m2) - 1, d);
    WT_ASSERT(!memcmp(d, two, 32));
    web_sha256("", 0, d);
    WT_ASSERT(!memcmp(d, empty, 32));

    static const struct { const char *in, *out; } b64[] = {
        { "", "" }, { "f", "Zg==" }, { "fo", "Zm8=" }, { "foo", "Zm9v" },
        { "foob", "Zm9vYg==" }, { "fooba", "Zm9vYmE=" },
        { "foobar", "Zm9vYmFy" },
    };
    for (size_t i = 0; i < sizeof(b64) / sizeof(b64[0]); i++) {
        char o[16];
        web_base64((const uint8_t *)b64[i].in, strlen(b64[i].in), o);
        WT_ASSERT(!strcmp(o, b64[i].out));
    }
}

/* The content of the page's single <tag> element. */
static int element(const char *tag, const char **start, size_t *len) {
    char open[16], close_[16];
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close_, sizeof(close_), "</%s>", tag);
    const char *o = strstr(page(), open);
    if (!o) return -1;
    o += strlen(open);
    const char *c = strstr(o, close_);
    if (!c) return -1;
    *start = o;
    *len = (size_t)(c - o);
    return 0;
}

static int count(const char *needle) {
    int n = 0;
    for (const char *p = page(); (p = strstr(p, needle)) != NULL; p++) n++;
    return n;
}

/* The CSP allows exactly the page's own inline blocks and nothing else:
 * default-src 'none', no 'unsafe-inline', and each hash recomputed here
 * from the served bytes. A page edit the embedder did not hash, or a
 * second block, would leave the browser refusing to run the page. Seen
 * red with 'unsafe-inline' added to the script-src web/tools/embed.c
 * writes. */
static void test_csp_hashes_match_the_page(void) {
    const char *csp = web_page_csp;
    WT_ASSERT(!strncmp(csp, "default-src 'none';", 19));
    WT_LACKS(csp, "unsafe-inline");
    WT_LACKS(csp, "unsafe-eval");
    WT_LACKS(csp, "http");
    WT_LACKS(csp, "*");
    WT_HAS(csp, "connect-src 'self'");
    WT_HAS(csp, "frame-ancestors 'none'");

    WT_EQ(count("<script"), 1);
    WT_EQ(count("</script>"), 1);
    WT_EQ(count("<style"), 1);
    WT_EQ(count("</style>"), 1);

    static const struct { const char *tag, *dir; } el[] = {
        { "script", "script-src" }, { "style", "style-src" },
    };
    for (size_t i = 0; i < 2; i++) {
        const char *b;
        size_t bl;
        WT_EQ(element(el[i].tag, &b, &bl), 0);
        uint8_t d[32];
        web_sha256(b, bl, d);
        char h[64], want[128];
        web_base64(d, 32, h);
        snprintf(want, sizeof(want), "%s 'sha256-%s'", el[i].dir, h);
        WT_HAS(csp, want);
    }

    /* The ETag is the leading half of the page digest, quoted. */
    uint8_t d[32];
    web_sha256(web_page, web_page_len, d);
    char want[40];
    want[0] = '"';
    for (int k = 0; k < 16; k++) snprintf(want + 1 + 2 * k, 3, "%02x", d[k]);
    want[33] = '"';
    want[34] = '\0';
    WT_ASSERT(!strcmp(web_page_etag, want));
}

/* ── /api/health ───────────────────────────────────────────────────────── */

static void test_health_json(void) {
    web_req_t rq;
    web_resp_t r;
    char out[4096];
    req(&rq, "/api/health", 0);
    WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_EQ(r.kind, WEB_R_ONESHOT);
    WT_ASSERT(r.body == NULL);
    static const char body[] =
        "{\"service\":\"slothweb\",\"milestone\":\"M0\",\"uptime_s\":42,"
        "\"socket\":\"none\",\"last_record_age_s\":null,"
        "\"db\":\"none\",\"db_schema\":null,\"db_rows\":null,"
        "\"sse_clients\":2,\"tick_seq\":17}\n";
    WT_HAS(out, "Content-Type: application/json\r\n");
    WT_HAS(out, "Cache-Control: no-store\r\n");
    WT_HAS(out, "Content-Security-Policy: default-src 'none'");
    char cl[64];
    snprintf(cl, sizeof(cl), "Content-Length: %zu\r\n", sizeof(body) - 1);
    WT_HAS(out, cl);
    char *sep = strstr(out, "\r\n\r\n");
    WT_ASSERT(sep && !strcmp(sep + 4, body));

    char head[4096];
    web_resp_t hr;
    req(&rq, "/api/health", 1);
    WT_EQ(web_route(&rq, &H, 1, head, sizeof(head), &hr), 0);
    WT_EQ(hr.out_len, r.out_len - (sizeof(body) - 1));
    WT_ASSERT(!memcmp(head, out, hr.out_len));
}

/* ── /events ───────────────────────────────────────────────────────────── */

static void test_events_opens_a_stream(void) {
    web_req_t rq;
    web_resp_t r;
    char out[4096];
    req(&rq, "/events", 0);
    WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.kind, WEB_R_SSE);
    WT_EQ(r.status, 200);
    WT_HAS(out, "HTTP/1.1 200 OK\r\n");
    WT_HAS(out, "Content-Type: text/event-stream; charset=utf-8\r\n");
    WT_HAS(out, "Cache-Control: no-cache\r\n");
    WT_HAS(out, "Connection: keep-alive\r\n");
    WT_LACKS(out, "Content-Length");
    static const char tail[] = "\r\n\r\nretry: 3000\n\n";
    WT_ASSERT(r.out_len > sizeof(tail) &&
              !strcmp(out + r.out_len - (sizeof(tail) - 1), tail));

    /* HEAD: the stream's headers, then the connection ends. */
    req(&rq, "/events", 1);
    WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.kind, WEB_R_ONESHOT);
    WT_EQ(r.status, 200);
    WT_HAS(out, "text/event-stream");
    WT_HAS(out, "Connection: close\r\n");
    WT_LACKS(out, "retry:");

    /* No room: 503, not a stream. Seen red (a stream) with the sse_room
     * test removed from route_events(). */
    req(&rq, "/events", 0);
    WT_EQ(web_route(&rq, &H, 0, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.kind, WEB_R_ONESHOT);
    WT_EQ(r.status, 503);
    WT_HAS(out, "HTTP/1.1 503 Service Unavailable\r\n");
}

/* The wire format of WHATWG HTML §9.2 (server-sent events): fields,
 * then a blank line; a line starting with ':' is a comment. */
static void test_event_formats(void) {
    char out[256];
    size_t n = web_sse_tick(out, sizeof(out), 7, 1700000000LL, &H);
    static const char tick[] =
        "id: 7\nevent: tick\n"
        "data: {\"seq\":7,\"ts\":1700000000,\"uptime_s\":42,\"sse_clients\":2}\n"
        "\n";
    WT_EQ(n, sizeof(tick) - 1);
    WT_ASSERT(!strcmp(out, tick));
    WT_EQ(web_sse_tick(out, 16, 7, 0, &H), 0);

    n = web_sse_ping(out, sizeof(out));
    WT_EQ(n, 8);
    WT_ASSERT(!strcmp(out, ": ping\n\n"));
    WT_EQ(web_sse_ping(out, 4), 0);
}

/* ── everything else ───────────────────────────────────────────────────── */

static void test_unknown_paths_are_404(void) {
    static const char *const paths[] = {
        "", "/index.html", "/api", "/api/", "/api/health/", "/api/live",
        "/events/", "/API/HEALTH", "//", "*", "/assets/app.js",
        "/favicon.ico", "/%61pi/health",
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        web_req_t rq;
        web_resp_t r;
        char out[4096];
        req(&rq, paths[i], 0);
        WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
        out[r.out_len] = '\0';
        WT_EQ(r.status, 404);
        WT_EQ(r.kind, WEB_R_ONESHOT);
        WT_HAS(out, "HTTP/1.1 404 Not Found\r\n");
    }
    /* A path that did not fit is 404 even if what was kept would match.
     * Seen red (200) with the path_long test removed from web_route(). */
    web_req_t rq;
    web_resp_t r;
    char out[4096];
    req(&rq, "/", 0);
    rq.path_long = 1;
    WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 404);
}

/* Routes do not change the read-only rule: a writing method never
 * reaches the router, whatever path it names. */
static void test_routes_are_still_405_for_writes(void) {
    static const char *const methods[] = { "POST", "PUT", "DELETE", "PATCH" };
    static const char *const paths[] = { "/", "/api/health", "/events" };
    for (size_t m = 0; m < 4; m++)
        for (size_t p = 0; p < 3; p++) {
            char rqs[256];
            snprintf(rqs, sizeof(rqs),
                     "%s %s HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
                     methods[m], paths[p]);
            int h;
            WT_EQ(web_http_classify(rqs, strlen(rqs), &h), 405);
        }
}

/* DNS rebinding: a page on attacker.example whose name now resolves to
 * 127.0.0.1 is admitted by the allow list (the peer is loopback) and is
 * same-origin with slothweb in the browser. Its requests carry its own
 * name in Host, and get nothing: not the page, not the health JSON, not
 * a stream, and not even a 404 that would tell it which paths exist.
 * Seen red (200, 200, 200, 404) with the web_http_host_ok() test
 * removed from web_route(). */
static void test_foreign_host_is_421(void) {
    static const char *const paths[] = { "/", "/api/health", "/events", "/x" };
    static const char *const hosts[] = {
        "attacker.example", "attacker.example:8770", "127.0.0.1.nip.io",
    };
    for (size_t p = 0; p < 4; p++)
        for (size_t h = 0; h < 3; h++)
            for (int is_head = 0; is_head < 2; is_head++) {
                web_req_t rq;
                web_resp_t r;
                char out[4096];
                req(&rq, paths[p], is_head);
                snprintf(rq.host, sizeof(rq.host), "%s", hosts[h]);
                WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
                out[r.out_len] = '\0';
                WT_EQ(r.status, 421);
                WT_EQ(r.kind, WEB_R_ONESHOT);
                WT_ASSERT(r.body == NULL);
                WT_HAS(out, "HTTP/1.1 421 Misdirected Request\r\n");
                WT_LACKS(out, "slothweb");
                WT_LACKS(out, "Access-Control");
            }

    /* An absolute-form authority replaces Host (RFC 9112 §3.2.2), in
     * both directions. Seen red (200) with web_route() checking rq->host
     * only. */
    web_req_t rq;
    web_resp_t r;
    char out[4096];
    req(&rq, "/api/health", 0);
    rq.target_abs = 1;
    snprintf(rq.target_host, sizeof(rq.target_host), "attacker.example");
    WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 421);
    req(&rq, "/api/health", 0);
    snprintf(rq.host, sizeof(rq.host), "attacker.example");
    rq.target_abs = 1;
    snprintf(rq.target_host, sizeof(rq.target_host), "[::1]:8770");
    WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 200);

    /* A value too long to keep is refused, not judged on a prefix.
     * Seen red (200) with the host_long test removed. */
    req(&rq, "/", 0);
    rq.host_long = 1;
    WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 421);
    req(&rq, "/", 0);
    rq.target_abs = 1;
    rq.target_host_long = 1;
    WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 421);
}

/* What the operator's browser sends is answered: the default bind, a
 * forwarded port, the name localhost, the v6 loopback and a remote
 * bind's own address. */
static void test_local_hosts_are_served(void) {
    static const char *const hosts[] = {
        "127.0.0.1:8770", "127.0.0.1:18770", "localhost:8770", "localhost",
        "[::1]:8770", "192.168.1.5:8770",
    };
    for (size_t h = 0; h < sizeof(hosts) / sizeof(hosts[0]); h++) {
        web_req_t rq;
        web_resp_t r;
        char out[4096];
        req(&rq, "/api/health", 0);
        snprintf(rq.host, sizeof(rq.host), "%s", hosts[h]);
        WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
        WT_EQ(r.status, 200);
    }
}

/* RFC 9112 §3.2: no Host, or more than one, is 400. Seen red (200)
 * with the host_count test removed from web_route(). */
static void test_host_count_must_be_one(void) {
    for (int count = 0; count <= 2; count += 2) {
        web_req_t rq;
        web_resp_t r;
        char out[4096];
        req(&rq, "/", 0);
        rq.host_count = count;
        WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), 0);
        out[r.out_len] = '\0';
        WT_EQ(r.status, 400);
        WT_HAS(out, "HTTP/1.1 400 Bad Request\r\n");
    }
}

static void test_small_buffer_is_an_error(void) {
    web_req_t rq;
    web_resp_t r;
    char out[64];
    static const char *const paths[] = { "/", "/api/health", "/events", "/x" };
    for (size_t i = 0; i < 4; i++) {
        req(&rq, paths[i], 0);
        WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), -1);
    }
}

void run_routes_tests(void) {
    WT_RUN(test_page_is_200_with_etag_and_csp);
    WT_RUN(test_page_304_on_matching_validator);
    WT_RUN(test_page_makes_no_external_reference);
    WT_RUN(test_font_is_the_system_monospace_stack);
    WT_RUN(test_design_tokens_match_spec);
    WT_RUN(test_sha256_and_base64_vectors);
    WT_RUN(test_csp_hashes_match_the_page);
    WT_RUN(test_health_json);
    WT_RUN(test_events_opens_a_stream);
    WT_RUN(test_event_formats);
    WT_RUN(test_unknown_paths_are_404);
    WT_RUN(test_routes_are_still_405_for_writes);
    WT_RUN(test_foreign_host_is_421);
    WT_RUN(test_local_hosts_are_served);
    WT_RUN(test_host_count_must_be_one);
    WT_RUN(test_small_buffer_is_an_error);
}
