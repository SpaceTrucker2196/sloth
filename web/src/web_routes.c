#include "web_routes.h"

#include <stdio.h>
#include <string.h>

#include "web_assets.h"

/* What every answer carries. no-referrer because nothing on the page
 * should tell anyone where it was; nosniff because every type is
 * declared. */
#define COMMON \
    "X-Content-Type-Options: nosniff\r\n" \
    "Referrer-Policy: no-referrer\r\n"

/* A JSON or event-stream answer is never a document: it can load
 * nothing and be framed by nothing. */
#define CSP_NONE "Content-Security-Policy: default-src 'none'; " \
                 "frame-ancestors 'none'\r\n"

static int fit(int n, size_t outsz, size_t *len) {
    if (n < 0 || (size_t)n >= outsz) return -1;
    *len = (size_t)n;
    return 0;
}

static int route_page(const web_req_t *rq, char *out, size_t outsz,
                      web_resp_t *r) {
    /* A validator that did not fit is treated as absent: the cost is a
     * 200 where a 304 would have done, never a wrong 304. */
    if (rq->inm_present && !rq->inm_long &&
        web_http_inm_matches(rq->inm, web_page_etag)) {
        r->status = 304;
        /* RFC 9110 §15.4.5: the headers a 200 would have carried that
         * describe caching, no body and no Content-Length. */
        return fit(snprintf(out, outsz,
            "HTTP/1.1 304 Not Modified\r\n"
            "ETag: %s\r\n"
            "Cache-Control: no-cache\r\n"
            COMMON
            "Connection: close\r\n"
            "\r\n", web_page_etag), outsz, &r->out_len);
    }
    r->status = 200;
    if (!rq->is_head) {
        r->body = web_page;
        r->body_len = web_page_len;
    }
    /* no-cache, not immutable: the page has no versioned URL, so the
     * browser revalidates every load and gets a 304 until a rebuild
     * changes the ETag. */
    return fit(snprintf(out, outsz,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "ETag: %s\r\n"
        "Cache-Control: no-cache\r\n"
        COMMON
        "Content-Security-Policy: %s\r\n"
        "Connection: close\r\n"
        "\r\n", web_page_len, web_page_etag, web_page_csp),
        outsz, &r->out_len);
}

static int health_json(const web_health_t *h, char *out, size_t outsz) {
    /* M0 has no data socket and no database yet; the fields that will
     * describe them are present and null so a client written now does
     * not change shape at M1. Nothing here comes from a peer, so
     * nothing needs escaping. */
    return snprintf(out, outsz,
        "{\"service\":\"slothweb\",\"milestone\":\"M0\","
        "\"uptime_s\":%lld,"
        "\"socket\":\"none\",\"last_record_age_s\":null,"
        "\"db\":\"none\",\"db_schema\":null,\"db_rows\":null,"
        "\"sse_clients\":%u,\"tick_seq\":%lu}\n",
        h->uptime_s, h->sse_clients, h->tick_seq);
}

static int route_health(const web_req_t *rq, const web_health_t *h,
                        char *out, size_t outsz, web_resp_t *r) {
    char body[512];
    int bl = health_json(h, body, sizeof(body));
    if (bl < 0 || (size_t)bl >= sizeof(body)) return -1;
    r->status = 200;
    return fit(snprintf(out, outsz,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Cache-Control: no-store\r\n"
        COMMON
        CSP_NONE
        "Connection: close\r\n"
        "\r\n"
        "%s", bl, rq->is_head ? "" : body), outsz, &r->out_len);
}

static int route_events(const web_req_t *rq, int sse_room, char *out,
                        size_t outsz, web_resp_t *r) {
    if (!rq->is_head && !sse_room) {
        r->status = 503;
        r->out_len = web_http_response(503, 0, out, outsz);
        return r->out_len ? 0 : -1;
    }
    r->status = 200;
    /* HEAD gets the stream's headers and the connection ends: there is
     * no length to promise and nothing to hold open. */
    if (!rq->is_head) r->kind = WEB_R_SSE;
    char retry[32] = "";
    if (!rq->is_head)
        snprintf(retry, sizeof(retry), "retry: %d\n\n", WEB_SSE_RETRY_MS);
    return fit(snprintf(out, outsz,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream; charset=utf-8\r\n"
        "Cache-Control: no-cache\r\n"
        COMMON
        CSP_NONE
        "Connection: %s\r\n"
        "\r\n"
        "%s",
        rq->is_head ? "close" : "keep-alive",
        retry), outsz, &r->out_len);
}

int web_route(const web_req_t *rq, const web_health_t *h, int sse_room,
              char *out, size_t outsz, web_resp_t *r) {
    memset(r, 0, sizeof(*r));
    r->kind = WEB_R_ONESHOT;
    /* RFC 9112 §3.2: an HTTP/1.1 request with no Host, or more than
     * one, is a 400. */
    if (rq->host_count != 1) {
        r->status = 400;
        r->out_len = web_http_response(400, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    /* DNS rebinding: the peer is loopback, so the allow list admits it,
     * but the page that sent the request may be another site's whose
     * name now resolves here. Its Host is that name. Refused before the
     * table, so such a page cannot even tell which paths exist. */
    const char *host = rq->target_abs ? rq->target_host : rq->host;
    int host_long = rq->target_abs ? rq->target_host_long : rq->host_long;
    if (host_long || !web_http_host_ok(host)) {
        r->status = 421;
        r->out_len = web_http_response(421, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    if (!rq->path_long) {
        if (!strcmp(rq->path, "/"))
            return route_page(rq, out, outsz, r);
        if (!strcmp(rq->path, "/api/health"))
            return route_health(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/events"))
            return route_events(rq, sse_room, out, outsz, r);
    }
    r->status = 404;
    r->out_len = web_http_response(404, rq->is_head, out, outsz);
    return r->out_len ? 0 : -1;
}

size_t web_sse_tick(char *out, size_t outsz, unsigned long seq, long long ts,
                    const web_health_t *h) {
    int n = snprintf(out, outsz,
        "id: %lu\n"
        "event: tick\n"
        "data: {\"seq\":%lu,\"ts\":%lld,\"uptime_s\":%lld,\"sse_clients\":%u}\n"
        "\n", seq, seq, ts, h->uptime_s, h->sse_clients);
    if (n < 0 || (size_t)n >= outsz) return 0;
    return (size_t)n;
}

size_t web_sse_ping(char *out, size_t outsz) {
    static const char ping[] = ": ping\n\n";
    if (outsz < sizeof(ping)) return 0;
    memcpy(out, ping, sizeof(ping));
    return sizeof(ping) - 1;
}
