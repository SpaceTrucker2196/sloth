/* The route table and the embedded page, without a socket
 * (web_routes.c, build/web/web_assets.c). test_server.c repeats the
 * important answers over a real loopback connection. */
#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "web_assets.h"
#include "web_routes.h"
#include "web_series.h"
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

static const web_health_t H = { 42, 2, 17, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL };

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
        " src=", "srcset", "@import", "url(", "@font-face",
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
    /* A link names a view of this page, a fragment, and fetches
     * nothing: href="#..." and no other. Seen red with a tile's href
     * made "/api/live". */
    int links = 0;
    for (const char *h = ci_find(p, n, " href="); h; ) {
        int frag = !strncmp(h, " href=\"#", 8);
        if (!frag) fprintf(stderr, "    a link that is not a fragment at byte %zu\n", (size_t)(h - p));
        WT_ASSERT(frag);
        links++;
        size_t at = (size_t)(h - p) + 6;
        h = at < n ? ci_find(h + 6, n - at, " href=") : NULL;
    }
    WT_ASSERT(links >= 6);

    /* The two places the page does talk to the server: same-origin,
     * relative paths. */
    WT_HAS(p, "new EventSource(\"/events\")");
    /* A page left closes its stream: one kept open by the browser's
     * back/forward cache held a connection per reload, and at the fifth
     * Chromium's six per host were gone and the new page's requests
     * never left (measured; seen red with the close removed). */
    WT_HAS(p, "  window.addEventListener(\"pagehide\", function () { if (es) { es.close(); es = null; } });");
    WT_HAS(p, "    if (e.persisted && !es) { openEvents(); live(); }");
    WT_HAS(p, "fetch(\"/api/health\"");
    /* /api/live through scoped(), which only ever adds "scope=" and one
     * of three constant words to the same relative path. */
    WT_HAS(p, "fetch(scoped(\"/api/live\")");
    WT_HAS(p, "return path + (path.indexOf(\"?\") >= 0 ? \"&\" : \"?\") + \"scope=\" + SCOPE;");
}

/* #159: stream strings (hostnames, SSIDs, alert details) are shown as
 * text. The JSON already carries < > & ' escaped (test_json.c), and the
 * page must not turn a decoded value back into markup: no sink that
 * parses HTML or code is in the script at all. Seen red with
 * li.innerHTML = r.text added to addRecord() in web/ui/app.js. */
static void test_page_renders_stream_values_as_text(void) {
    const char *p = page();
    size_t n = web_page_len;
    static const char *const sinks[] = {
        "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
        "createContextualFragment", "DOMParser", "eval(", "new Function",
        "setAttribute(", "setTimeout(\"", "setInterval(\"", ".src =",
        ".href =", "srcdoc",
    };
    for (size_t i = 0; i < sizeof(sinks) / sizeof(sinks[0]); i++) {
        const char *hit = ci_find(p, n, sinks[i]);
        if (hit)
            fprintf(stderr, "    page contains \"%s\" at byte %zu\n",
                    sinks[i], (size_t)(hit - p));
        WT_ASSERT(hit == NULL);
    }
    WT_HAS(p, ".textContent = String(");
    /* The one class name chosen by a stream value comes from a fixed
     * table, never from the value itself. */
    WT_HAS(p, "Object.prototype.hasOwnProperty.call(TYPE_CLASS, t)");
}

/* §8.1 as amended by the 2026-10-21 fonts ruling: no font file and no
 * font request. The 2026-10-23 restyle (the owner's Spacetrucker
 * system) names Fira Code first, which is used only where it is
 * installed: the name appears once, inside --font-mono, and nothing on
 * the page can fetch it. Seen red with an @font-face block added to
 * web/ui/theme.css (the "fira" count and the @font-face ban). */
static void test_font_is_the_system_monospace_stack(void) {
    WT_HAS(page(), "--font-mono: \"Fira Code\", ui-monospace, \"SF Mono\", Menlo, "
                   "\"DejaVu Sans Mono\", monospace;");
    WT_HAS(page(), "font-family: var(--font-mono);");
    int fira = 0;
    for (const char *h = page(); (h = ci_find(h, web_page_len - (size_t)(h - page()), "fira"));
         h += 4)
        fira++;
    WT_EQ(fira, 1);
    WT_ASSERT(ci_find(page(), web_page_len, "@font-face") == NULL);
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

/* The chrome tokens as served: the page's semantic names, mapped onto
 * the owner's Spacetrucker system (the 2026-10-23 Design ruling;
 * docs/web-ui-spec.md §8.1, amended 2026-10-26, points here and at
 * web/ui/theme.css). The data colours are not here: they are generated
 * from the TUI's sources and compared with the TUI itself in
 * test_tui_colors.c. */
static void test_design_tokens_are_spacetrucker(void) {
    static const struct { const char *name, *value; } tok[] = {
        { "--void", "#050208" },        { "--void-2", "#0a0512" },
        { "--dim", "#8a82a0" },         { "--dimmer", "#5a536e" },
        { "--phosphor-hi", "#d9fff3" }, { "--phosphor-mid", "#43d6a8" },
        { "--ice", "#4cebff" },         { "--violet", "#996bff" },
        { "--brass", "#b88c40" },       { "--amber", "#ff8c26" },
        { "--dusk-teal", "#0f6f7a" },   { "--dusk-magenta", "#ff3fa8" },
        { "--paper", "#f4f0e6" },
        { "--bg", "var(--void)" },      { "--panel", "#0e0817" },
        { "--rule", "#163a30" },        { "--rule-hi", "var(--dimmer)" },
        { "--ink", "#e8e2f2" },         { "--muted", "var(--dim)" },
        { "--faint", "var(--dimmer)" }, { "--signal", "var(--amber)" },
        { "--data", "var(--ice)" },     { "--phosphor", "#6bffcc" },
        { "--phosphor-dim", "#2b8f74" },
        { "--sev-low", "var(--heat-1)" }, { "--sev-warn", "var(--heat-2)" },
        { "--sev-crit", "var(--heat-3)" },
        { "--radius", "14px" },         { "--gap", "8px" },
    };
    WT_HAS(page(), ":root {");
    WT_HAS(page(), ":root[data-theme=\"light\"] {");
    for (size_t i = 0; i < sizeof(tok) / sizeof(tok[0]); i++) {
        char v[64];
        int rc = token(tok[i].name, v, sizeof(v));
        WT_EQ(rc, 0);
        if (rc == 0 && strcmp(v, tok[i].value))
            fprintf(stderr, "    %s is \"%s\", the design says %s\n",
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
        "{\"service\":\"slothweb\",\"milestone\":\"M6\",\"uptime_s\":42,"
        "\"socket\":\"none\",\"last_record_age_s\":null,"
        "\"db\":\"none\",\"db_schema\":null,\"db_rows\":null,"
        "\"db_supported\":[1,8],\"sql\":false,"
        "\"store\":\"none\",\"anomaly\":null,\"sse_clients\":2,"
        "\"tick_seq\":17}\n";
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
        "", "/index.html", "/api", "/api/", "/api/health/", "/api/live/",
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
    static const char *const paths[] = { "/", "/api/health", "/api/live",
                                         "/events" };
    for (size_t m = 0; m < 4; m++)
        for (size_t p = 0; p < 4; p++) {
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
    static const char *const paths[] = { "/", "/api/health", "/api/live",
                                         "/events", "/x" };
    static const char *const hosts[] = {
        "attacker.example", "attacker.example:8770", "127.0.0.1.nip.io",
    };
    for (size_t p = 0; p < 5; p++)
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
    static const char *const paths[] = { "/", "/api/health", "/api/live",
                                         "/events", "/x" };
    for (size_t i = 0; i < 5; i++) {
        req(&rq, paths[i], 0);
        WT_EQ(web_route(&rq, &H, 1, out, sizeof(out), &r), -1);
    }
}


/* ── /api/anomalies, /api/baseline, the anomaly event (M3) ──────────── */

static char g_big[65536];

static void qreq(web_req_t *rq, const char *path, const char *query,
                 int is_head) {
    req(rq, path, is_head);
    snprintf(rq->query, sizeof(rq->query), "%s", query);
}

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

typedef struct {
    web_baseline_t bl;
    web_ident_t    id;
    web_anomaly_t  an;
    web_health_t   h;
} eng_t;

static void eng_up(eng_t *e, int cap) {
    memset(e, 0, sizeof(*e));
    WT_EQ(web_baseline_init(&e->bl, 64), 0);
    WT_EQ(web_ident_init(&e->id, 8, 8), 0);
    web_anom_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.bl = &e->bl;
    c.ident = &e->id;
    c.max_keys = 16;
    WT_EQ(web_anomaly_init(&e->an, cap, &c), 0);
    e->h = H;
    e->h.anomaly = &e->an;
    e->h.wall_s = 1792627200;
}

static void eng_down(eng_t *e) {
    web_anomaly_destroy(&e->an);
    web_ident_destroy(&e->id);
    web_baseline_destroy(&e->bl);
}

/* The audit found no test that routed this path at all: a NULL engine,
 * the strict query, HEAD and the content type were all unexercised.
 * The 400s seen red with the query check in route_anomalies() turned
 * off; the 503 with its NULL test removed (a crash). */
static void test_anomalies_route(void) {
    web_req_t rq;
    web_resp_t r;
    qreq(&rq, "/api/anomalies", "", 0);
    WT_EQ(web_route(&rq, &H, 1, g_big, sizeof(g_big), &r), 0);
    g_big[r.out_len] = '\0';
    WT_EQ(r.status, 503);
    WT_HAS(body_of(g_big), "{\"error\":\"no_anomaly_engine\"}");

    eng_t e;
    eng_up(&e, 8);
    e.an.ep[0] = (web_anom_ep_t){ .id = 3, .state = WEB_EP_OPEN,
        .rule = WEB_ANOM_A1_RATE, .metric = WM_HOST_CONNS, .key = "10.0.0.5",
        .score = 61, .peak = 70, .evidence = "host.conns[10.0.0.5] z=3.1\n<x>",
        .first_seen = 1792627000, .last_seen = 1792627100 };
    WT_EQ(web_route(&rq, &e.h, 1, g_big, sizeof(g_big), &r), 0);
    g_big[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_HAS(g_big, "Content-Type: application/json\r\n");
    WT_HAS(g_big, "Cache-Control: no-store\r\n");
    const char *b = body_of(g_big);
    WT_HAS(b, "{\"now\":1792627200,\"since\":1792623600,\"anomalies\":[{\"id\":3,"
              "\"rule\":\"A1\",\"kind\":\"rate\",\"metric\":\"host.conns\","
              "\"key\":\"10.0.0.5\",\"score\":61,\"peak\":70,");
    WT_HAS(b, "z=3.1\\n\\u003cx\\u003e\"");
    WT_HAS(b, "\"state\":\"open\",\"open\":true}],\"more\":false,\"omitted\":0}");
    size_t full = r.out_len, blen = strlen(b);

    qreq(&rq, "/api/anomalies", "", 1);
    WT_EQ(web_route(&rq, &e.h, 1, g_big, sizeof(g_big), &r), 0);
    WT_EQ(r.status, 200);
    WT_EQ(r.out_len, full - blen);

    static const char *const bad[][2] = {
        { "x=1", "unknown_parameter" }, { "kind=vendors", "unknown_kind" },
        { "since=abc", "bad_since" }, { "since=1&since=2", "repeated_parameter" },
        { "kind=", "empty_value" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        qreq(&rq, "/api/anomalies", bad[i][0], 0);
        WT_EQ(web_route(&rq, &e.h, 1, g_big, sizeof(g_big), &r), 0);
        g_big[r.out_len] = '\0';
        WT_EQ(r.status, 400);
        WT_HAS(body_of(g_big), bad[i][1]);
    }
    qreq(&rq, "/api/anomalies", "", 0);
    rq.query_long = 1;
    WT_EQ(web_route(&rq, &e.h, 1, g_big, sizeof(g_big), &r), 0);
    g_big[r.out_len] = '\0';
    WT_EQ(r.status, 400);
    WT_HAS(body_of(g_big), "query_too_long");

    qreq(&rq, "/api/anomalies", "kind=dns&since=1792600000", 0);
    WT_EQ(web_route(&rq, &e.h, 1, g_big, sizeof(g_big), &r), 0);
    g_big[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_HAS(body_of(g_big), "\"since\":1792600000,\"anomalies\":[]");
    eng_down(&e);
}

/* The worst case through the route: a 200 that stops with "more", never
 * the 503 the previous slice answered past 276 episodes. */
static void test_anomalies_route_worst_case(void) {
    eng_t e;
    eng_up(&e, WEB_ANOM_CAP);
    for (int i = 0; i < e.an.cap; i++) {
        web_anom_ep_t *x = &e.an.ep[i];
        x->id = i + 1;
        x->state = WEB_EP_OPEN;
        x->rule = WEB_ANOM_A1_RATE;
        x->metric = WM_HOST_CONNS;
        snprintf(x->key, sizeof(x->key), "2001:db8:aaaa:bbbb:cccc:dddd:%04x:%04x",
                 i, i);
        memset(x->evidence, '&', WEB_ANOM_EVIDENCE_MAX);
        x->evidence[WEB_ANOM_EVIDENCE_MAX] = '\0';
    }
    web_req_t rq;
    web_resp_t r;
    qreq(&rq, "/api/anomalies", "", 0);
    WT_EQ(web_route(&rq, &e.h, 1, g_big, sizeof(g_big), &r), 0);
    WT_EQ(r.status, 200);
    WT_ASSERT(r.out_len < sizeof(g_big));
    g_big[r.out_len < sizeof(g_big) ? r.out_len : sizeof(g_big) - 1] = '\0';
    WT_HAS(body_of(g_big), "\"more\":true");
    eng_down(&e);
}

static void test_baseline_route(void) {
    web_req_t rq;
    web_resp_t r;
    qreq(&rq, "/api/baseline", "metric=host.conns&key=10.0.0.5", 0);
    WT_EQ(web_route(&rq, &H, 1, g_big, sizeof(g_big), &r), 0);
    WT_EQ(r.status, 503);
    eng_t e;
    eng_up(&e, 8);
    static const char *const bad[][2] = {
        { "", "missing_metric" }, { "metric=nope", "unknown_metric" },
        { "metric=host.conns&key=not-an-ip", "bad_key" },
        { "metric=conns.total&key=1", "bad_key" },
        { "metric=host.conns&tier=hour", "unknown_parameter" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        qreq(&rq, "/api/baseline", bad[i][0], 0);
        WT_EQ(web_route(&rq, &e.h, 1, g_big, sizeof(g_big), &r), 0);
        g_big[r.out_len] = '\0';
        WT_EQ(r.status, 400);
        WT_HAS(body_of(g_big), bad[i][1]);
    }
    qreq(&rq, "/api/baseline", "metric=host.conns&key=10.0.0.5", 0);
    WT_EQ(web_route(&rq, &e.h, 1, g_big, sizeof(g_big), &r), 0);
    g_big[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_HAS(body_of(g_big), "\"fed\":false,\"cells\":null}");
    /* Thursday 14:00 UTC (the suite's zone): cell 3 * 24 + 14. */
    web_baseline_feed(&e.bl, WM_HOST_CONNS, "10.0.0.5", 1792677600, 5, 1);
    WT_EQ(web_route(&rq, &e.h, 1, g_big, sizeof(g_big), &r), 0);
    g_big[r.out_len] = '\0';
    const char *b = body_of(g_big);
    WT_HAS(b, "{\"metric\":\"host.conns\",\"key\":\"10.0.0.5\",\"kind\":\"gauge\"");
    WT_HAS(b, "\"now_cell\":72,\"utc_offset_s\":0,\"fed\":true,\"cells\":[[0,0,0,0],");
    /* [mean, sd, n, sd_hour]: a gauge's minute and hour spreads, both
     * at the floor of one unit for a single sample. */
    WT_HAS(b, ",[5,1,1,1],");
    int cells = 0;
    for (const char *p = strstr(b, "\"cells\":["); p && (p = strstr(p + 1, "]")); )
        cells++;
    WT_EQ(cells, WEB_BL_CELLS + 1);
    eng_down(&e);
}

/* The M3 page: the elements app.js draws into and the two fetches it
 * makes, as the served page carries them (both halves of each name:
 * the HTML's id and the script's lookup of it), and the exact query
 * shapes those fetches send, answered 200. A rename on one side only
 * left the suite green before. Each seen red with the id renamed in
 * index.html, and with the fetch prefix misspelt in app.js. */
static void test_page_carries_the_m3_view(void) {
    const char *p = page();
    static const char *const ids[] = {
        "v-anomalies", "n-cards", "n-chips", "o-heat", "sens", "k-tp-spark"
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        char want[64];
        snprintf(want, sizeof(want), "id=\"%s\"", ids[i]);
        WT_HAS(p, want);
        if (i == 0) continue;                 /* looked up as "v-" + view */
        snprintf(want, sizeof(want), "$(\"%s\")", ids[i]);
        WT_HAS(p, want);
    }
    WT_HAS(p, "\"anomalies\"");               /* in the views it shows */
    WT_HAS(p, "\"/api/anomalies?since=\" + (now - win)");
    WT_HAS(p, "p += \"&kind=\" + encodeURIComponent(kind)");
    WT_HAS(p, "\"/api/baseline?metric=\" + encodeURIComponent(m)");
    WT_HAS(p, "p += \"&key=\" + encodeURIComponent(key)");

    /* The shapes those build: since alone, since and kind, metric
     * alone (a global series) and metric and key. */
    eng_t e;
    eng_up(&e, 8);
    web_req_t rq;
    web_resp_t r;
    static const char *const q[][2] = {
        { "/api/anomalies", "since=1792623600" },
        { "/api/anomalies", "since=1792623600&kind=rate" },
        { "/api/baseline", "metric=conns.total" },
        { "/api/baseline", "metric=iface.rx_rate&key=eth0" },
    };
    for (size_t i = 0; i < sizeof(q) / sizeof(q[0]); i++) {
        qreq(&rq, q[i][0], q[i][1], 0);
        WT_EQ(web_route(&rq, &e.h, 1, g_big, sizeof(g_big), &r), 0);
        WT_EQ(r.status, 200);
    }
    eng_down(&e);
}

/* The page's cellOf(), the server's cell for a point: its UTC hour
 * bucket's local hour of the week. Pinned as the page carries it, then
 * cross-checked, in C, against /api/baseline's now_cell in a half-hour
 * zone (IST, +5:30) for every 10 minutes of a week: the page reads the
 * cell the server scores. cellOf(t) taken from t itself (t + off) is a
 * different cell for the second half of every UTC hour there, which
 * the last assertion shows. Seen red with app.js's expression changed
 * to (t + off) (the pinned source no longer found). */
static int js_cell_of(long long t, long long off) {
    long long u = t - t % 3600 + off;          /* new Date(u * 1000) */
    long long day = u >= 0 ? u / 86400 : -((-u + 86399) / 86400);
    int wday = (int)(((day + 4) % 7 + 7) % 7); /* getUTCDay(): 1970-01-01 a Thursday */
    int hour = (int)(((u % 86400) + 86400) % 86400 / 3600);
    return ((wday + 6) % 7) * 24 + hour;
}

/* The chord label rule, as served and as a C port of it: a label longer
 * than its room keeps its tail from a separator, after an ellipsis, so
 * what shows is visibly part of an address and never a whole address it
 * is not. A cut never starts on the first colon of "::" (the tail would
 * be a valid compressed IPv6 address), and with no separator that fits
 * the head is kept instead (a tail cut mid-label, like 8.51.100.1 from
 * 198.51.100.1, reads as another address). Seen red with the old '~' +
 * tail rule and with the "::" skip removed. */
static size_t c_cut_label(const char *id, size_t maxc, char *out, size_t cap) {
    size_t n = strlen(id);
    if (n <= maxc) return (size_t)snprintf(out, cap, "%s", id);
    for (size_t i = 1; i < n; i++) {
        if (id[i] == ':' && id[i + 1] == ':') continue;
        if ((id[i] == '.' || id[i] == ':') && n - i + 1 <= maxc)
            return (size_t)snprintf(out, cap, "...%s", id + i);
    }
    return (size_t)snprintf(out, cap, "%.*s...", (int)(maxc - 1), id);
}

static void test_page_chord_labels(void) {
    WT_HAS(page(), "      if (c === \":\" && id.charAt(i + 1) === \":\") continue;\n"
                   "      if ((c === \".\" || c === \":\") && id.length - i + 1 <= maxc) "
                   "return \"\\u2026\" + id.slice(i);\n"
                   "    }\n"
                   "    return id.slice(0, maxc - 1) + \"\\u2026\";");
    char o[96];
    c_cut_label("198.51.100.1", 11, o, sizeof(o));
    WT_EQ(strcmp(o, "....51.100.1"), 0);
    c_cut_label("2001:db8:cafe::ab:1234", 11, o, sizeof(o));
    WT_LACKS(o, "...::");
    WT_EQ(strcmp(o, "...:ab:1234"), 0);
    c_cut_label("192.0.2.123456789", 6, o, sizeof(o));   /* no separator fits */
    WT_EQ(strcmp(o, "192.0..."), 0);
    c_cut_label("10.0.0.1", 11, o, sizeof(o));
    WT_EQ(strcmp(o, "10.0.0.1"), 0);
}

static void test_page_cell_matches_the_servers_cell(void) {
    WT_HAS(page(), "function cellOf(t, off) {\n"
                   "    var d = new Date((t - t % 3600 + off) * 1000);\n"
                   "    return ((d.getUTCDay() + 6) % 7) * 24 + d.getUTCHours();\n"
                   "  }");
    WT_HAS(page(), "bl.cells[cellOf(pts[i][0], bl.utc_offset_s || 0)]");
    setenv("TZ", "IST-5:30", 1);
    tzset();
    static char out[16384];
    int checked = 0, differs = 0;
    const long long mon = 1792454400LL;        /* Tuesday 2026-10-20 00:00 UTC */
    for (long long t = mon; t < mon + 7 * 86400; t += 600) {
        size_t n = web_baseline_json(NULL, WM_HOST_CONNS, "10.0.0.5", t, out,
                                     sizeof(out));
        if (n == 0 || n >= sizeof(out)) {
            WT_ASSERT(!"the baseline answer did not fit");
            break;
        }
        out[n] = '\0';
        const char *c = strstr(out, "\"now_cell\":");
        const char *o = strstr(out, "\"utc_offset_s\":");
        long long cell = -1, off = 0;
        if (!c || !o || sscanf(c, "\"now_cell\":%lld", &cell) != 1 ||
            sscanf(o, "\"utc_offset_s\":%lld", &off) != 1) {
            WT_ASSERT(!"now_cell or utc_offset_s missing");
            break;
        }
        if (off != 19800 || js_cell_of(t, off) != cell) {
            WT_EQ(off, 19800);
            WT_EQ(js_cell_of(t, off), cell);
            break;
        }
        checked++;
        long long u = t + off;
        int naive = (int)((((u / 86400) + 4) % 7 + 6) % 7) * 24 +
                    (int)(u % 86400 / 3600);
        differs += naive != cell;
    }
    setenv("TZ", "UTC0", 1);
    tzset();
    WT_EQ(checked, 7 * 144);
    WT_EQ(differs, 7 * 72);
}

/* A cell that is not a finite number (none can be made: a restored one
 * past a float's range is refused) still answers JSON: null, never a
 * bare inf. Seen red with jw_num()'s isfinite() test removed. */
static void test_baseline_route_never_prints_inf(void) {
    eng_t e;
    eng_up(&e, 8);
    web_baseline_feed(&e.bl, WM_HOST_CONNS, "10.0.0.5", 1792677600, 5, 1);
    e.bl.chunk[0][0].cell[web_bl_cell_index(1792677600)].mean = INFINITY;
    web_req_t rq;
    web_resp_t r;
    qreq(&rq, "/api/baseline", "metric=host.conns&key=10.0.0.5", 0);
    WT_EQ(web_route(&rq, &e.h, 1, g_big, sizeof(g_big), &r), 0);
    g_big[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_HAS(body_of(g_big), ",[null,");
    WT_LACKS(body_of(g_big), "inf");
    eng_down(&e);
}

/* §7.1's anomaly event: one data line, whatever the evidence holds. */
static void test_anomaly_event_and_tick(void) {
    web_anom_ep_t x = { .id = 9, .state = WEB_EP_CLOSED, .rule = WEB_ANOM_A6_NAMES,
        .metric = -1, .key = "10.0.0.9", .evidence = "a\r\nb" };
    char ev[WEB_ANOM_EP_JSON_MAX + 128];
    size_t n = web_sse_anomaly(ev, sizeof(ev), &x);
    WT_ASSERT(n > 0);
    WT_ASSERT(!strncmp(ev, "event: anomaly\ndata: {\"id\":9,\"rule\":\"A6\","
                           "\"kind\":\"ident\",\"metric\":null,", 60));
    int lf = 0;
    for (size_t i = 0; i < n; i++) lf += ev[i] == '\n';
    WT_EQ(lf, 3);
    WT_HAS(ev, "\"evidence\":\"a\\r\\nb\"");
    WT_HAS(ev, "\"open\":false}\n\n");
    eng_t e;
    eng_up(&e, 8);
    e.an.ep[0] = x;
    e.an.ep[0].state = WEB_EP_OPEN;
    char t[1024];
    WT_ASSERT(web_sse_tick(t, sizeof(t), 1, 5, &e.h) > 0);
    WT_HAS(t, "\"anomalies_open\":1}");
    web_req_t rq;
    web_resp_t r;
    req(&rq, "/api/health", 0);
    WT_EQ(web_route(&rq, &e.h, 1, g_big, sizeof(g_big), &r), 0);
    g_big[r.out_len] = '\0';
    WT_HAS(g_big, "\"anomaly\":{\"open\":1,\"building\":0,\"closed_kept\":0,"
                  "\"cap\":8,");
    WT_HAS(g_big, "\"baseline\":{\"entries\":0,\"cap\":64,");
    WT_HAS(g_big, "\"ident\":{\"macs\":0,\"mac_cap\":8,\"mac_evictions\":0,");
    WT_HAS(g_big, "\"persisted\":false");
    eng_down(&e);
}

void run_routes_tests(void) {
    WT_RUN(test_page_is_200_with_etag_and_csp);
    WT_RUN(test_page_304_on_matching_validator);
    WT_RUN(test_page_makes_no_external_reference);
    WT_RUN(test_page_renders_stream_values_as_text);
    WT_RUN(test_font_is_the_system_monospace_stack);
    WT_RUN(test_design_tokens_are_spacetrucker);
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
    WT_RUN(test_anomalies_route);
    WT_RUN(test_anomalies_route_worst_case);
    WT_RUN(test_baseline_route);
    WT_RUN(test_page_carries_the_m3_view);
    WT_RUN(test_baseline_route_never_prints_inf);
    WT_RUN(test_page_cell_matches_the_servers_cell);
    WT_RUN(test_page_chord_labels);
    WT_RUN(test_anomaly_event_and_tick);
}
