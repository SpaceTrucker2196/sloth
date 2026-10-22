#include "web_routes.h"

#include <stdio.h>
#include <string.h>

#include "web_assets.h"
#include "web_json.h"
#include "web_series.h"

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

/* The M2 members: the store and the rollup's bounds. "store" is
 * "none" with no time series at all, "memory" with the rollup but no
 * slothweb.db, "open" with both. */
static void kc_obj(web_jw_t *w, const char *name, const long long v[WEB_KC_COUNT]) {
    web_jw_raw(w, ",");
    web_jw_key(w, name);
    for (int c = 0; c < WEB_KC_COUNT; c++) {
        web_jw_raw(w, c ? "," : "{");
        web_jw_key(w, web_kclass_name(c));
        web_jw_int(w, v[c]);
    }
    web_jw_raw(w, "}");
}

static void tsdb_health(web_tsdb_t *t, web_jw_t *w) {
    if (!t) {
        web_jw_raw(w, "\"store\":\"none\"");
        return;
    }
    web_rollup_stats_t rs;
    web_rollup_stats(t->ru, &rs);
    web_store_stats_t ss;
    memset(&ss, 0, sizeof(ss));
    int open = t->store && t->store->rd;
    if (open) web_store_stats(t->store, &ss);
    web_jw_raw(w, "\"store\":");
    web_jw_str(w, open ? "open" : "memory");
    web_jw_raw(w, ",\"store_path\":");
    /* Operator text, shown cut; the full path is on stderr at start. */
    if (open) web_jw_strn(w, t->store->path, strnlen(t->store->path, 256));
    else      web_jw_raw(w, "null");
    web_jw_raw(w, ",\"store_schema\":");
    if (open) web_jw_int(w, ss.schema); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"store_rows\":");
    if (open) {
        web_jw_raw(w, "{\"fine\":");    web_jw_int(w, ss.rows[WEB_TIER_FINE]);
        web_jw_raw(w, ",\"minute\":");  web_jw_int(w, ss.rows[WEB_TIER_MINUTE]);
        web_jw_raw(w, ",\"hour\":");    web_jw_int(w, ss.rows[WEB_TIER_HOUR]);
        web_jw_raw(w, "}");
    } else {
        web_jw_raw(w, "null");
    }
    web_jw_raw(w, ",\"store_bytes\":");     web_jw_int(w, ss.bytes);
    web_jw_raw(w, ",\"store_max_bytes\":"); web_jw_int(w, t->max_bytes);
    web_jw_raw(w, ",\"store_batches\":");   web_jw_int(w, (long long)ss.batches);
    web_jw_raw(w, ",\"store_write_errors\":");
    web_jw_int(w, (long long)ss.write_errors);
    web_jw_raw(w, ",\"store_last_error\":");
    if (ss.last_error[0]) web_jw_str(w, ss.last_error); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"store_compactions\":");
    web_jw_int(w, (long long)ss.compactions);
    web_jw_raw(w, ",\"store_dropped_expired\":");
    web_jw_int(w, (long long)ss.dropped_expired);
    web_jw_raw(w, ",\"store_dropped_ceiling\":");
    web_jw_int(w, (long long)ss.dropped_ceiling);
    web_jw_raw(w, ",\"store_ceiling_runs\":");
    web_jw_int(w, (long long)ss.ceiling_runs);
    web_jw_raw(w, ",\"retain_days\":");     web_jw_int(w, t->retain_days);
    long long v[WEB_KC_COUNT];
    for (int c = 0; c < WEB_KC_COUNT; c++) v[c] = rs.keys[c];
    kc_obj(w, "series_keys", v);
    for (int c = 0; c < WEB_KC_COUNT; c++) v[c] = rs.caps[c];
    kc_obj(w, "series_key_caps", v);
    for (int c = 0; c < WEB_KC_COUNT; c++) v[c] = (long long)rs.evictions[c];
    kc_obj(w, "key_evictions", v);
    web_jw_raw(w, ",\"series\":");           web_jw_int(w, (long long)rs.series);
    web_jw_raw(w, ",\"samples\":");          web_jw_int(w, (long long)rs.samples);
    web_jw_raw(w, ",\"ring_rows\":");        web_jw_int(w, (long long)rs.ring_rows);
    web_jw_raw(w, ",\"queue_rows\":");       web_jw_int(w, (long long)rs.queue_rows);
    web_jw_raw(w, ",\"queue_dropped\":");    web_jw_int(w, (long long)rs.q_dropped);
    web_jw_raw(w, ",\"churn_dropped\":");  web_jw_int(w, (long long)rs.churn_dropped);
    web_jw_raw(w, ",\"highwater_evictions\":");
    web_jw_int(w, (long long)rs.hw_evictions);
    web_jw_raw(w, ",\"values_clamped\":");   web_jw_int(w, (long long)rs.clamped);
}

static size_t health_json(const web_health_t *h, char *out, size_t outsz) {
    web_jw_t w;
    web_jw_init(&w, out, outsz);
    web_jw_raw(&w, "{\"service\":\"slothweb\",\"milestone\":\"M2\",\"uptime_s\":");
    web_jw_int(&w, h->uptime_s);
    /* With no data socket the M0 shape stands: "none" and null. Every
     * stream-derived or operator-given string goes through web_jw_str. */
    if (h->live) web_live_health_members(h->live, &w, h->now_ms);
    else         web_jw_raw(&w, ",\"socket\":\"none\",\"last_record_age_s\":null");
    web_jw_raw(&w, ",\"db\":\"none\",\"db_schema\":null,\"db_rows\":null,");
    tsdb_health(h->tsdb, &w);
    web_jw_raw(&w, ",\"sse_clients\":");
    web_jw_int(&w, h->sse_clients);
    web_jw_raw(&w, ",\"tick_seq\":");
    web_jw_int(&w, (long long)h->tick_seq);
    web_jw_raw(&w, "}\n");
    return w.overflow ? 0 : w.len;
}

static int route_health(const web_req_t *rq, const web_health_t *h,
                        char *out, size_t outsz, web_resp_t *r) {
    char body[8192];
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

/* A JSON answer whose body was rendered at out + WEB_LIVE_HDR_RESERVE:
 * write the header in front of it. */
static int json_answer(const web_req_t *rq, int status, size_t bl, char *out,
                       size_t outsz, web_resp_t *r) {
    char *body = out + WEB_LIVE_HDR_RESERVE;
    char hdr[WEB_LIVE_HDR_RESERVE];
    size_t hl;
    if (fit(snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        COMMON
        CSP_NONE
        "Connection: close\r\n"
        "\r\n", status, web_http_reason(status), bl), sizeof(hdr), &hl) != 0)
        return -1;
    if (hl + bl > outsz) return -1;
    r->status = status;
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

enum { SR_SERIES, SR_KEYS, SR_METRICS };

/* /api/series, /api/keys, /api/metrics. Every parameter is checked
 * before anything is read (web_series.h); a bad one is a 400 naming the
 * reason in a word of our own, never echoing the value. */
static int route_series(const web_req_t *rq, const web_health_t *h, int which,
                        char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    char why[48] = "";
    size_t bl = 0;
    int status = 200;
    if (!h->tsdb) {
        status = 503;
        bl = web_series_error_json("no_time_series", body, cap);
    } else if (rq->query_long) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
    } else if (which == SR_SERIES) {
        web_series_q_t q;
        int store_on = h->tsdb->store && h->tsdb->store->rd;
        if (web_series_parse(rq->query, h->wall_s, h->tsdb->retain_days,
                             store_on, &q, why, sizeof(why)) != 0) {
            status = 400;
            bl = web_series_error_json(why, body, cap);
        } else {
            bl = web_series_json(h->tsdb, &q, body, cap);
        }
    } else if (which == SR_KEYS) {
        int metric;
        if (web_keys_parse(rq->query, &metric, why, sizeof(why)) != 0) {
            status = 400;
            bl = web_series_error_json(why, body, cap);
        } else {
            bl = web_keys_json(h->tsdb, metric, body, cap);
        }
    } else {
        if (web_metrics_parse(rq->query, why, sizeof(why)) != 0) {
            status = 400;
            bl = web_series_error_json(why, body, cap);
        } else {
            bl = web_metrics_json(h->tsdb, body, cap);
        }
    }
    if (bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, status, bl, out, outsz, r);
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
        if (!strcmp(rq->path, "/api/series"))
            return route_series(rq, h, SR_SERIES, out, outsz, r);
        if (!strcmp(rq->path, "/api/keys"))
            return route_series(rq, h, SR_KEYS, out, outsz, r);
        if (!strcmp(rq->path, "/api/metrics"))
            return route_series(rq, h, SR_METRICS, out, outsz, r);
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
