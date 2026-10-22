#include "web_routes.h"

#include <stdio.h>
#include <string.h>

#include "web_assets.h"
#include "web_json.h"

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

static size_t health_json(const web_health_t *h, char *out, size_t outsz) {
    web_jw_t w;
    web_jw_init(&w, out, outsz);
    web_jw_raw(&w, "{\"service\":\"slothweb\",\"milestone\":\"M1\",\"uptime_s\":");
    web_jw_int(&w, h->uptime_s);
    /* With no data socket the M0 shape stands: "none" and null. Every
     * stream-derived or operator-given string goes through web_jw_str. */
    if (h->live) web_live_health_members(h->live, &w, h->now_ms);
    else         web_jw_raw(&w, ",\"socket\":\"none\",\"last_record_age_s\":null");
    web_jw_raw(&w, ",\"db\":\"none\",\"db_schema\":null,\"db_rows\":null,"
                   "\"sse_clients\":");
    web_jw_int(&w, h->sse_clients);
    web_jw_raw(&w, ",\"tick_seq\":");
    web_jw_int(&w, (long long)h->tick_seq);
    web_jw_raw(&w, "}\n");
    return w.overflow ? 0 : w.len;
}

static int route_health(const web_req_t *rq, const web_health_t *h,
                        char *out, size_t outsz, web_resp_t *r) {
    char body[4096];
    size_t bl = health_json(h, body, sizeof(body));
    if (bl == 0) return -1;
    r->status = 200;
    return fit(snprintf(out, outsz,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        COMMON
        CSP_NONE
        "Connection: close\r\n"
        "\r\n"
        "%s", bl, rq->is_head ? "" : body), outsz, &r->out_len);
}

static size_t live_body(const web_health_t *h, char *out, size_t cap) {
    if (h->live) return web_live_json(h->live, out, cap, h->now_ms);
    static const char none[] =
        "{\"socket\":\"none\",\"devices\":null,\"devices_stale\":true,"
        "\"alerts_open\":null,\"records\":0,\"records_s\":null,"
        "\"sensor\":{\"state\":\"unknown\"},\"alerts\":[],\"recent\":[]}\n";
    if (cap < sizeof(none)) return 0;
    memcpy(out, none, sizeof(none));
    return sizeof(none) - 1;
}

/* The body is rendered straight into out behind room for the header,
 * then the header is written in front of it: one copy, no second 64 KB
 * buffer. */
static int route_live(const web_req_t *rq, const web_health_t *h,
                      char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t bl = live_body(h, body, outsz - WEB_LIVE_HDR_RESERVE);
    if (bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    char hdr[WEB_LIVE_HDR_RESERVE];
    size_t hl;
    if (fit(snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        COMMON
        CSP_NONE
        "Connection: close\r\n"
        "\r\n", bl), sizeof(hdr), &hl) != 0)
        return -1;
    r->status = 200;
    if (rq->is_head) {
        memcpy(out, hdr, hl);
        r->out_len = hl;
        return 0;
    }
    memmove(out + hl, body, bl);
    memcpy(out, hdr, hl);
    r->out_len = hl + bl;
    return 0;
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
        if (!strcmp(rq->path, "/api/live"))
            return route_live(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/events"))
            return route_events(rq, sse_room, out, outsz, r);
    }
    r->status = 404;
    r->out_len = web_http_response(404, rq->is_head, out, outsz);
    return r->out_len ? 0 : -1;
}

size_t web_sse_tick(char *out, size_t outsz, unsigned long seq, long long ts,
                    const web_health_t *h) {
    char data[512];
    web_jw_t w;
    web_jw_init(&w, data, sizeof(data));
    web_jw_raw(&w, "{\"seq\":");        web_jw_int(&w, (long long)seq);
    web_jw_raw(&w, ",\"ts\":");         web_jw_int(&w, ts);
    web_jw_raw(&w, ",\"uptime_s\":");   web_jw_int(&w, h->uptime_s);
    web_jw_raw(&w, ",\"sse_clients\":"); web_jw_int(&w, h->sse_clients);
    if (h->live) {
        web_live_sum_t s;
        char r10[32];
        web_live_summary(h->live, &s, h->now_ms);
        web_jw_raw(&w, ",\"socket\":"); web_jw_str(&w, web_live_sock_word(s.sock_state));
        web_jw_raw(&w, ",\"devices\":");
        if (s.dev_known) web_jw_int(&w, s.devices); else web_jw_raw(&w, "null");
        web_jw_raw(&w, ",\"devices_stale\":"); web_jw_raw(&w, s.dev_stale ? "true" : "false");
        web_jw_raw(&w, ",\"alerts_open\":[");
        web_jw_int(&w, (long long)s.alerts[0]); web_jw_raw(&w, ",");
        web_jw_int(&w, (long long)s.alerts[1]); web_jw_raw(&w, ",");
        web_jw_int(&w, (long long)s.alerts[2]); web_jw_raw(&w, "]");
        snprintf(r10, sizeof(r10), "%ld.%ld", s.rate10 / 10, s.rate10 % 10);
        web_jw_raw(&w, ",\"records_s\":"); web_jw_raw(&w, r10);
        web_jw_raw(&w, ",\"records\":"); web_jw_int(&w, (long long)s.records);
        web_jw_raw(&w, ",\"sensor\":"); web_jw_str(&w, s.sensor);
    }
    web_jw_raw(&w, "}");
    if (w.overflow) return 0;
    int n = snprintf(out, outsz, "id: %lu\nevent: tick\ndata: %s\n\n", seq, data);
    if (n < 0 || (size_t)n >= outsz) return 0;
    return (size_t)n;
}

size_t web_sse_record(char *out, size_t outsz, const web_live_rec_t *e) {
    /* The escaped JSON holds no raw CR or LF (web_jw_strn escapes both),
     * so it is one SSE data line whatever the record said. */
    char data[(WEB_LIVE_TYPE_MAX + WEB_LIVE_TEXT_MAX) * WEB_JW_EXPAND + 128];
    web_jw_t w;
    web_jw_init(&w, data, sizeof(data));
    web_jw_raw(&w, "{\"seq\":");  web_jw_int(&w, (long long)e->seq);
    web_jw_raw(&w, ",\"type\":"); web_jw_str(&w, e->type);
    web_jw_raw(&w, ",\"ts\":");   web_jw_int(&w, e->ts);
    web_jw_raw(&w, ",\"text\":"); web_jw_str(&w, e->text);
    web_jw_raw(&w, "}");
    if (w.overflow) return 0;
    int n = snprintf(out, outsz, "event: record\ndata: %s\n\n", data);
    if (n < 0 || (size_t)n >= outsz) return 0;
    return (size_t)n;
}

size_t web_sse_ping(char *out, size_t outsz) {
    static const char ping[] = ": ping\n\n";
    if (outsz < sizeof(ping)) return 0;
    memcpy(out, ping, sizeof(ping));
    return sizeof(ping) - 1;
}
