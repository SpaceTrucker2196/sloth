/* /api/series, /api/keys, /api/metrics (#160, M2): parameter
 * validation, the answer's shape and bounds, the routes behind the W0
 * and M0 checks, and the spec §12 M2 acceptance: an hour of records
 * driven through the decoder on a pinned clock, then the 24 h chart's
 * request answered at 10 s (from the store's fine tier as well as from
 * memory) and the store under 5 MB on disk, its WAL included, at every
 * step of the hour. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "web_http.h"
#include "web_ingest.h"
#include "web_live.h"
#include "web_metrics.h"
#include "web_rollup.h"
#include "web_routes.h"
#include "web_series.h"
#include "web_server.h"
#include "web_store.h"
#include "web_tsdb.h"
#include "wtest.h"

static const long long T = 1792627200;   /* a whole hour, unix seconds */

static int parse(const char *q, long long now, int store_on,
                 web_series_q_t *out, char *why) {
    return web_series_parse(q, now, 30, store_on, out, why, 48);
}

static void bad(const char *q, int store_on, const char *want) {
    web_series_q_t s;
    char why[48] = "";
    int rc = parse(q, T + 5, store_on, &s, why);
    WT_EQ(rc, -1);
    if (strcmp(why, want))
        fprintf(stderr, "  query \"%s\": got %s, want %s\n", q, why, want);
    WT_ASSERT(!strcmp(why, want));
}

static void test_parameters_validated(void) {
    web_series_q_t s;
    char why[48];
    WT_EQ(parse("metric=conns.total", T + 5, 0, &s, why), 0);
    WT_EQ(s.metric, WM_CONNS_TOTAL);
    WT_EQ(s.tier, WEB_TIER_FINE);
    WT_EQ(s.to, T + 10);                 /* the end of the bucket filling */
    WT_EQ(s.from, T + 10 - 3600);
    WT_ASSERT(s.key[0] == '\0');
    WT_EQ(parse("metric=dev.frames&key=AA%3ABB%3acc%3Add%3Aee%3AFF", T, 0,
                &s, why), 0);
    WT_ASSERT(!strcmp(s.key, "aa:bb:cc:dd:ee:ff"));
    WT_EQ(parse("metric=host.rx_rate&key=10.0.0.1&from=100&to=200", T, 0,
                &s, why), 0);
    WT_EQ(s.from, 100);
    WT_EQ(s.to, 200);
    WT_EQ(parse("tier=minute&metric=wifi.ap_count&key=6g37", T, 1, &s, why), 0);
    WT_EQ(s.tier, WEB_TIER_MINUTE);
    WT_EQ(s.from, T + 60 - 86400);
    WT_EQ(parse("metric=iface.rx_rate&key=eth0&from=1000&to=87410", T, 0,
                &s, why), 0);                   /* 24 h and one bucket */

    bad("", 0, "missing_metric");
    bad("key=eth0", 0, "missing_metric");
    bad("metric=nope", 0, "unknown_metric");
    bad("metric=CONNS.TOTAL", 0, "unknown_metric");
    bad("metric=conns.total&key=x", 0, "bad_key");
    bad("metric=host.rx_rate", 0, "bad_key");
    bad("metric=host.rx_rate&key=10.0.0.256", 0, "bad_key");
    bad("metric=host.rx_rate&key=%3Cscript%3E", 0, "bad_key");
    bad("metric=conns.total&metric=conns.total", 0, "repeated_parameter");
    bad("metric=conns.total&x=1", 0, "unknown_parameter");
    bad("Metric=conns.total", 0, "unknown_parameter");
    bad("metric=conns.total&sql=1", 0, "unknown_parameter");
    bad("metric", 0, "bad_query");
    bad("=x", 0, "bad_query");
    bad("metric=conns.total&", 0, "bad_query");
    bad("metric=conns.total&&tier=fine", 0, "bad_query");
    bad("metric=", 0, "empty_value");
    bad("metric=conns%2", 0, "bad_escape");
    bad("metric=conns%zz", 0, "bad_escape");
    bad("metric=conns%20total", 0, "bad_value");
    bad("metric=conns%00", 0, "bad_value");
    bad("metric=conns%7F", 0, "bad_value");
    bad("metric=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        0, "value_too_long");
    bad("metric=conns.total&tier=10s", 0, "unknown_tier");
    bad("metric=conns.total&tier=minute", 0, "tier_unavailable");
    bad("metric=conns.total&tier=hour", 0, "tier_unavailable");
    bad("metric=conns.total&from=abc", 0, "bad_from");
    bad("metric=conns.total&from=-5&to=10", 0, "bad_from");
    bad("metric=conns.total&from=123456789012&to=1", 0, "bad_from");
    bad("metric=conns.total&to=1e9", 0, "bad_to");
    bad("metric=conns.total&from=10&to=10", 0, "empty_range");
    bad("metric=conns.total&from=20&to=10", 0, "empty_range");
    bad("metric=conns.total&from=1792627000&to=1792713606", 0, "to_in_future");
    bad("metric=conns.total&from=1000&to=87411", 0, "range_too_long");
    bad("metric=conns.total&tier=minute&from=0&to=2592061", 1, "range_too_long");

    int m;
    WT_EQ(web_keys_parse("metric=host.conns", &m, why, sizeof(why)), 0);
    WT_EQ(m, WM_HOST_CONNS);
    WT_EQ(web_keys_parse("metric=host.conns&key=1", &m, why, sizeof(why)), -1);
    WT_EQ(web_keys_parse("", &m, why, sizeof(why)), -1);
    WT_EQ(web_metrics_parse("", why, sizeof(why)), 0);
    WT_EQ(web_metrics_parse("x=1", why, sizeof(why)), -1);
}

static web_rollup_t ru;
static web_tsdb_t   ts;
static char         body[65536];

static void mem_tsdb(void) {
    char err[64];
    WT_EQ(web_rollup_init(&ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, NULL, 30, 256, NULL, NULL), 0);
}

static void mem_done(void) {
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
}

/* The shape, oldest first; value by kind; paging past 900. */
static void test_series_json_and_paging(void) {
    mem_tsdb();
    for (int b = 0; b < 1000; b++) {
        web_rollup_add(&ru, WM_HOST_RX, "10.0.0.1", 1.5, T + b * 10);
        web_rollup_add(&ru, WM_HOST_RX, "10.0.0.1", 2.5, T + b * 10 + 1);
    }
    web_series_q_t q;
    char why[48];
    WT_EQ(parse("metric=host.rx_rate&key=10.0.0.1&from=1792627200&to=1792637200",
                T + 9999, 0, &q, why), 0);
    size_t n = web_series_json(&ts, &q, body, sizeof(body));
    WT_ASSERT(n > 0);
    body[n] = '\0';
    WT_HAS(body, "{\"metric\":\"host.rx_rate\",\"key\":\"10.0.0.1\",\"tier\":\"fine\","
                 "\"step\":10,\"kind\":\"gauge\",\"unit\":\"B/s\",");
    WT_HAS(body, "\"source\":\"memory\"");
    WT_HAS(body, "\"more\":true");
    /* The newest 900: buckets 100..999, the open one included. */
    char want[96];
    snprintf(want, sizeof(want), "\"next_to\":%lld,", T + 1000);
    WT_HAS(body, want);
    snprintf(want, sizeof(want), "\"points\":[[%lld,2,1.5,2.5,2],", T + 1000);
    WT_HAS(body, want);
    snprintf(want, sizeof(want), "[%lld,2,1.5,2.5,2]]}", T + 9990);
    WT_HAS(body, want);
    int pts = 0;
    for (const char *p = body; (p = strstr(p, ",2,1.5,2.5,2]")); p++) pts++;
    WT_EQ(pts, WEB_SERIES_MAX_POINTS);
    /* The next page, to=next_to: the rest. */
    WT_EQ(parse("metric=host.rx_rate&key=10.0.0.1&from=1792627200&to=1792628200",
                T + 9999, 0, &q, why), 0);
    n = web_series_json(&ts, &q, body, sizeof(body));
    body[n] = '\0';
    WT_HAS(body, "\"more\":false,\"next_to\":null,");
    pts = 0;
    for (const char *p = body; (p = strstr(p, ",2,1.5,2.5,2]")); p++) pts++;
    WT_EQ(pts, 100);
    /* A counter reads as its sum. */
    web_rollup_add(&ru, WM_DNS_QUERIES, "10.0.0.1", 1, T + 3);
    web_rollup_add(&ru, WM_DNS_QUERIES, "10.0.0.1", 1, T + 4);
    WT_EQ(parse("metric=dns.queries&key=10.0.0.1&from=1792627200&to=1792627210",
                T + 5, 0, &q, why), 0);
    n = web_series_json(&ts, &q, body, sizeof(body));
    body[n] = '\0';
    snprintf(want, sizeof(want), "\"kind\":\"counter\"");
    WT_HAS(body, want);
    snprintf(want, sizeof(want), "\"points\":[[%lld,2,1,1,2]]}", T);
    WT_HAS(body, want);
    /* No series yet: an empty list, not an error. */
    WT_EQ(parse("metric=host.rx_rate&key=10.9.9.9", T, 0, &q, why), 0);
    n = web_series_json(&ts, &q, body, sizeof(body));
    body[n] = '\0';
    WT_HAS(body, "\"points\":[]}");
    mem_done();
}

/* A request, through the parser, into the router. */
static web_resp_t route(const web_health_t *h, const char *raw, char *out,
                        size_t outsz) {
    web_req_t rq;
    web_resp_t r;
    memset(&r, 0, sizeof(r));
    WT_EQ(web_http_parse(raw, strlen(raw), &rq), WEB_HTTP_ROUTE);
    /* One byte held back for the NUL, the answer's room otherwise the
     * server's own (a connection's out[]). */
    WT_EQ(web_route(&rq, h, 1, out, outsz - 1, &r), 0);
    out[r.out_len] = '\0';
    return r;
}

static char out[WEB_SSE_MAX_UNSENT + 1];

static void test_routes(void) {
    mem_tsdb();
    web_rollup_add(&ru, WM_HOST_CONNS, "10.0.0.1", 3, T);
    web_rollup_add(&ru, WM_HOST_CONNS, "10.0.0.2", 4, T + 1);
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.tsdb = &ts;
    h.wall_s = T + 5;
    web_resp_t r = route(&h, "GET /api/series?metric=host.conns&key=10.0.0.1 HTTP/1.1\r\n"
                             "Host: 127.0.0.1:8770\r\n\r\n", out, sizeof(out));
    WT_EQ(r.status, 200);
    WT_HAS(out, "Content-Type: application/json\r\n");
    WT_HAS(out, "Cache-Control: no-store\r\n");
    WT_HAS(out, "Content-Security-Policy: default-src 'none'");
    char want[96];
    snprintf(want, sizeof(want), "\"points\":[[%lld,3,3,3,1]]}", T);
    WT_HAS(out, want);
    size_t full = r.out_len;
    char *sep = strstr(out, "\r\n\r\n");
    WT_ASSERT(sep != NULL);
    r = route(&h, "HEAD /api/series?metric=host.conns&key=10.0.0.1 HTTP/1.1\r\n"
                  "Host: 127.0.0.1\r\n\r\n", out, sizeof(out));
    WT_EQ(r.status, 200);
    WT_EQ(r.out_len, (size_t)(sep - out) + 4);
    WT_ASSERT(r.out_len < full);

    /* A refusal names the reason in our words; the value is not echoed. */
    r = route(&h, "GET /api/series?metric=host.conns&key=%3Cscript%3Ealert(1)%3C/script%3E"
                  " HTTP/1.1\r\nHost: localhost\r\n\r\n", out, sizeof(out));
    WT_EQ(r.status, 400);
    WT_HAS(out, "{\"error\":\"bad_key\"}");
    WT_LACKS(out, "script");
    WT_LACKS(out, "alert");

    char big[1200];
    int o = snprintf(big, sizeof(big), "GET /api/series?metric=host.conns&key=");
    while (o < 700) big[o++] = 'a';
    snprintf(big + o, sizeof(big) - (size_t)o, " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    r = route(&h, big, out, sizeof(out));
    WT_EQ(r.status, 400);
    WT_HAS(out, "query_too_long");

    r = route(&h, "GET /api/keys?metric=host.conns HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
              out, sizeof(out));
    WT_EQ(r.status, 200);
    WT_HAS(out, "{\"metric\":\"host.conns\",\"keykind\":\"ip\",\"total\":2,\"keys\":"
                "[{\"key\":\"10.0.0.2\",");
    r = route(&h, "GET /api/metrics HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", out, sizeof(out));
    WT_EQ(r.status, 200);
    WT_HAS(out, "{\"store\":false,");
    WT_HAS(out, "{\"name\":\"minute\",\"step\":60,\"keep_s\":2592000,\"available\":false}");
    for (int i = 0; i < WM_COUNT; i++) {
        snprintf(want, sizeof(want), "{\"name\":\"%s\",", web_metric_defs[i].name);
        WT_HAS(out, want);
    }
    WT_HAS(out, "{\"name\":\"host.conns\",\"kind\":\"gauge\",\"keykind\":\"ip\"");
    r = route(&h, "GET /api/metrics?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", out, sizeof(out));
    WT_EQ(r.status, 400);

    /* The W0/M0 checks come first on the new routes too: a foreign Host
     * is 421, every writing method 405. */
    static const char *const paths[] = {
        "/api/series?metric=conns.total", "/api/keys?metric=host.conns", "/api/metrics",
    };
    for (int i = 0; i < 3; i++) {
        char rq[256];
        snprintf(rq, sizeof(rq), "GET %s HTTP/1.1\r\nHost: attacker.example\r\n\r\n",
                 paths[i]);
        r = route(&h, rq, out, sizeof(out));
        WT_EQ(r.status, 421);
        WT_LACKS(out, "{");
        static const char *const verbs[] = { "POST", "PUT", "DELETE", "PATCH" };
        for (int v = 0; v < 4; v++) {
            int is_head = 0;
            snprintf(rq, sizeof(rq), "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                     verbs[v], paths[i]);
            WT_EQ(web_http_classify(rq, strlen(rq), &is_head), 405);
        }
    }

    /* Without a time series (no tsdb attached): 503. */
    h.tsdb = NULL;
    r = route(&h, "GET /api/series?metric=conns.total HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
              out, sizeof(out));
    WT_EQ(r.status, 503);
    WT_HAS(out, "no_time_series");
    /* /api/health carries the M2 members. */
    h.tsdb = &ts;
    r = route(&h, "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", out, sizeof(out));
    WT_EQ(r.status, 200);
    WT_HAS(out, "\"store\":\"memory\",\"store_path\":null,");
    WT_HAS(out, "\"series_key_caps\":{\"global\":1,\"device\":64,\"host\":32,"
                "\"iface\":32,\"channel\":64,\"alert\":128}");
    WT_HAS(out, "\"key_evictions\":{\"global\":0,\"device\":0,\"host\":0,"
                "\"iface\":0,\"channel\":0,\"alert\":0}");
    WT_HAS(out, "\"key_returns\":{\"global\":0,\"device\":0,\"host\":0,"
                "\"iface\":0,\"channel\":0,\"alert\":0}");
    WT_HAS(out, "\"queue_rows\":0,\"queue_cap\":0,");
    WT_HAS(out, "\"queue_dropped\":0,\"churn_dropped\":0,");
    /* The ceiling's raised passes and the analysis state's measured size
     * (none without a store: -1). */
    WT_HAS(out, "\"store_ceiling_runs\":0,\"store_ceiling_raised\":0,"
                "\"store_analysis_bytes\":-1,");
    mem_done();
}

#ifdef WITH_SQLITE
/* The answer's worst case fits: 900 points, every number at its widest. */
static void test_worst_case_fits(void) {
    char dir[64] = "/tmp/slothweb-series-XXXXXX";
    WT_ASSERT(mkdtemp(dir) != NULL);
    char p[128], err[512];
    snprintf(p, sizeof(p), "%s/w.db", dir);
    static web_store_t st;
    char e2[64];
    WT_EQ(web_store_open(&st, p, err, sizeof(err)), 0);
    WT_EQ(web_rollup_init(&ru, 64, 1, e2, sizeof(e2)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, &st, 30, 256, NULL, NULL), 0);
    static web_qrow_t r[1000];
    for (int i = 0; i < 1000; i++) {
        memset(&r[i], 0, sizeof(r[i]));
        r[i].tier = WEB_TIER_FINE;
        r[i].metric = WM_HOST_RX;
        snprintf(r[i].key, sizeof(r[i].key), "1234:5678:9abc:def0:1234:5678:9abc:def0");
        r[i].t = 9999990000LL - i * 10;
        r[i].sum = -3.7037035e-300;
        r[i].n = 4294967295UL;
        r[i].min = -1.2345679e-300;
        r[i].max = -1.2345679e-300;
    }
    WT_EQ(web_store_write(&st, r, 1000), 0);
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.tsdb = &ts;
    h.wall_s = 9999990000LL;
    web_resp_t rr = route(&h, "GET /api/series?metric=host.rx_rate&key="
                              "1234:5678:9abc:def0:1234:5678:9abc:def0"
                              "&from=9999903610&to=9999990010 HTTP/1.1\r\n"
                              "Host: 127.0.0.1\r\n\r\n", out, sizeof(out));
    WT_EQ(rr.status, 200);
    WT_HAS(out, "\"more\":true");
    WT_HAS(out, ",-1.234568e-300,-1.234568e-300,4294967295]]}");
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    web_store_close(&st);
    unlink(p);
    char s2[160];
    snprintf(s2, sizeof(s2), "%s-wal", p); unlink(s2);
    snprintf(s2, sizeof(s2), "%s-shm", p); unlink(s2);
    rmdir(dir);
}

static int count_points(const char *b, long long *oldest, long long *newest) {
    const char *pt = strstr(b, "\"points\":[");
    int c = 0;
    *oldest = *newest = -1;
    for (const char *q = pt ? pt + 10 : NULL; q && (q = strchr(q, '[')); q++) {
        long long t = atoll(q + 1);
        if (*oldest < 0) *oldest = t;
        *newest = t;
        c++;
    }
    return c;
}

/* The 900-point cap holds on the merged answer, not only on each half:
 * the store holds 900 older fine buckets of a series and the ring 900
 * newer ones (899 closed and the one filling), so the union is 1800.
 * The answer is the newest 900, more is set and next_to is the oldest
 * returned bucket; the page below it is the store's 900. Seen red with
 * the merge loop's cap raised to 2 * max (1800 points came back). */
static void test_merged_answer_capped(void) {
    char dir[64] = "/tmp/slothweb-merge-XXXXXX";
    WT_ASSERT(mkdtemp(dir) != NULL);
    char p[128], err[512], e2[64], why[48];
    snprintf(p, sizeof(p), "%s/m.db", dir);
    static web_store_t st;
    WT_EQ(web_store_open(&st, p, err, sizeof(err)), 0);
    WT_EQ(web_rollup_init(&ru, 64, 0, e2, sizeof(e2)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, &st, 30, 256, NULL, NULL), 0);
    const int M = WEB_SERIES_MAX_POINTS;
    static web_qrow_t r[WEB_SERIES_MAX_POINTS];
    for (int i = 0; i < M; i++) {
        memset(&r[i], 0, sizeof(r[i]));
        r[i].tier = WEB_TIER_FINE;
        r[i].metric = WM_HOST_RX;
        snprintf(r[i].key, sizeof(r[i].key), "10.0.0.1");
        r[i].t = T + (long long)i * 10;
        r[i].sum = r[i].min = r[i].max = 1;
        r[i].n = 1;
    }
    WT_EQ(web_store_write(&st, r, (size_t)M), 0);
    const long long mid = T + (long long)M * 10;
    for (int i = 0; i < M; i++)
        web_rollup_add(&ru, WM_HOST_RX, "10.0.0.1", 2, mid + (long long)i * 10);
    const long long end = mid + (long long)M * 10;

    web_series_q_t q;
    char qs[160];
    snprintf(qs, sizeof(qs), "metric=host.rx_rate&key=10.0.0.1&from=%lld&to=%lld",
             T, end);
    WT_EQ(parse(qs, end - 1, 1, &q, why), 0);
    size_t n = web_series_json(&ts, &q, body, sizeof(body));
    WT_ASSERT(n > 0);
    body[n < sizeof(body) ? n : sizeof(body) - 1] = '\0';
    WT_HAS(body, "\"source\":\"store+memory\"");
    WT_HAS(body, "\"more\":true");
    long long lo, hi;
    WT_EQ(count_points(body, &lo, &hi), M);
    WT_EQ(lo, mid);
    WT_EQ(hi, end - 10);
    char want[64];
    snprintf(want, sizeof(want), "\"next_to\":%lld,", mid);
    WT_HAS(body, want);
    WT_ASSERT(strstr(body, ",1,1,1,1]") == NULL);   /* no store point yet */

    snprintf(qs, sizeof(qs), "metric=host.rx_rate&key=10.0.0.1&from=%lld&to=%lld",
             T, mid);
    WT_EQ(parse(qs, end - 1, 1, &q, why), 0);
    n = web_series_json(&ts, &q, body, sizeof(body));
    WT_ASSERT(n > 0);
    body[n < sizeof(body) ? n : sizeof(body) - 1] = '\0';
    WT_HAS(body, "\"more\":false,\"next_to\":null,");
    WT_EQ(count_points(body, &lo, &hi), M);
    WT_EQ(lo, T);
    WT_EQ(hi, mid - 10);
    WT_ASSERT(strstr(body, ",2,2,2,1]") == NULL);   /* no ring point */

    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    web_store_close(&st);
    unlink(p);
    char s2[160];
    snprintf(s2, sizeof(s2), "%s-wal", p); unlink(s2);
    snprintf(s2, sizeof(s2), "%s-shm", p); unlink(s2);
    rmdir(dir);
}

/* A burst of evictions is written before the 10 s timer: once
 * WEB_FLUSH_HIGH rows are queued, the next step writes them. 20,000 new
 * host keys of one sample each, a second after a flush, each evicting
 * one and so closing its 10 s row; the next step writes them all though
 * the next flush is nine seconds off. Seen red with the high-water
 * clause taken out of web_tsdb_step() (19,744 rows still queued). */
static void test_queue_high_water_flushes_early(void) {
    char dir[64] = "/tmp/slothweb-high-XXXXXX";
    WT_ASSERT(mkdtemp(dir) != NULL);
    char p[128], err[512], e2[64];
    snprintf(p, sizeof(p), "%s/h.db", dir);
    static web_store_t st;
    WT_EQ(web_store_open(&st, p, err, sizeof(err)), 0);
    WT_EQ(web_rollup_init(&ru, WEB_DEFAULT_MAX_KEYS, 1, e2, sizeof(e2)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, &st, 30, 256, NULL, NULL), 0);
    web_tsdb_step(&ts, T);                      /* next flush at T+10 */
    char k[32];
    for (int i = 0; i < 20000; i++) {
        snprintf(k, sizeof(k), "10.%d.%d.%d", i >> 16, (i >> 8) & 255, i & 255);
        web_rollup_add(&ru, WM_DNS_QUERIES, k, 1, T + 1);
    }
    WT_ASSERT(web_rollup_queued(&ru) >= WEB_FLUSH_HIGH);
    web_tsdb_step(&ts, T + 1);
    WT_EQ(web_rollup_queued(&ru), 0);
    WT_ASSERT(web_store_count(&st, WEB_TIER_FINE) >= 20000 - 256);
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    web_store_close(&st);
    unlink(p);
    char s2[160];
    snprintf(s2, sizeof(s2), "%s-wal", p); unlink(s2);
    snprintf(s2, sizeof(s2), "%s-shm", p); unlink(s2);
    rmdir(dir);
}

/* One sample of every metric for every key its class can hold at
 * --web-max-keys 8192, at now; how many series that is. */
static size_t sample_all_keys(long long now) {
    char k[WEB_KEY_MAX + 1];
    size_t n = 0;
    for (int m = 0; m < WM_COUNT; m++) {
        int kc = web_metric_defs[m].kclass;
        int cap = kc == WEB_KC_GLOBAL ? 1 : kc == WEB_KC_DEV ? WEB_MAX_KEYS_MAX
                : kc == WEB_KC_HOST ? WEB_MAX_KEYS_MAX / 2
                : kc == WEB_KC_IFACE ? WEB_IFACE_KEYS
                : kc == WEB_KC_CHANNEL ? WEB_CHANNEL_KEYS : WEB_ALERT_KEYS;
        for (int i = 0; i < cap; i++) {
            switch (kc) {
            case WEB_KC_GLOBAL:  k[0] = '\0'; break;
            case WEB_KC_DEV:     snprintf(k, sizeof(k), "02:00:00:00:%02x:%02x",
                                          i >> 8, i & 0xff); break;
            case WEB_KC_HOST:    snprintf(k, sizeof(k), "10.0.%d.%d", i >> 8,
                                          i & 0xff); break;
            case WEB_KC_IFACE:   snprintf(k, sizeof(k), "eth%d", i); break;
            default:             snprintf(k, sizeof(k), "%d", i + 1); break;
            }
            web_rollup_add(&ru, m, k, 1, now);
            n++;
        }
    }
    return n;
}

/* Shutdown writes what is queued before close_all() adds its rows: the
 * queue is sized for close_all()'s rows on their own
 * (web_rollup.h), not on top of a backlog. Every series at --web-max-
 * keys 8192, sampled every 10 s for 40 s inside one minute with no
 * flush, leaves four fine rows a series queued; web_tsdb_flush_all() on
 * a real store then loses nothing, and every series' open fine, minute
 * and hour bucket is in the store. Seen red with the leading flush()
 * removed from web_tsdb_flush_all(): queue_dropped 74,050, and the
 * fine tier 296,200 rows of 370,250 (every series' open one lost). */
static void test_flush_all_writes_backlog_first(void) {
    char dir[64] = "/tmp/slothweb-fall-XXXXXX";
    WT_ASSERT(mkdtemp(dir) != NULL);
    char p[128], err[512], e2[64];
    snprintf(p, sizeof(p), "%s/f.db", dir);
    static web_store_t st;
    WT_EQ(web_store_open(&st, p, err, sizeof(err)), 0);
    WT_EQ(web_rollup_init(&ru, WEB_MAX_KEYS_MAX, 1, e2, sizeof(e2)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, &st, 30, 256, NULL, NULL), 0);
    const long long B = T + 600;                 /* a whole minute */
    size_t series = 0;
    for (long long now = B; now <= B + 40; now += 10)
        series = sample_all_keys(now);
    web_rollup_stats_t rs;
    web_rollup_stats(&ru, &rs);
    WT_EQ(rs.series, series);
    WT_EQ(rs.q_dropped, 0);
    WT_EQ(rs.queue_rows, 4 * series);
    /* More than close_all()'s rows fit beside: the order matters. */
    WT_ASSERT(rs.queue_rows + 3 * series > rs.queue_cap);
    web_tsdb_flush_all(&ts);
    web_rollup_stats(&ru, &rs);
    WT_EQ(rs.q_dropped, 0);
    WT_EQ(rs.queue_rows, 0);
    WT_EQ(web_store_count(&st, WEB_TIER_FINE), 5 * (long long)series);
    WT_EQ(web_store_count(&st, WEB_TIER_MINUTE), series);
    WT_EQ(web_store_count(&st, WEB_TIER_HOUR), series);
    web_point_t pt[2];
    int more;
    WT_EQ(web_store_query(&st, WEB_TIER_HOUR, WM_HOST_RX, "10.0.15.255",
                          T, T + 3600, pt, 2, &more), 1);
    WT_EQ(pt[0].t, T);
    WT_EQ(pt[0].n, 5);
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    web_store_close(&st);
    unlink(p);
    char s2[160];
    snprintf(s2, sizeof(s2), "%s-wal", p); unlink(s2);
    snprintf(s2, sizeof(s2), "%s-shm", p); unlink(s2);
    rmdir(dir);
}
#endif

/* ── spec §12, M2 ───────────────────────────────────────────────────────
 * "After 1 h of running, the 24 h chart shows the last hour at 10 s
 * resolution and the store is under 5 MB." An hour of a small home
 * network's records goes through the real framer and decoder, a pass
 * every 2 s, with the store thread's step run every second, all on a
 * pinned clock. Per pass: 15 connections, 2 interfaces, 20 top hosts,
 * 30 devices, 10 probe clients (frame_count rising), 3 channels, one
 * DNS query from one of 5 hosts in turn, and sensor_health. That is
 * 117 series that each get a sample in every 10 s bucket. */
static long long g_now;
static long long pinned(void *ctx) { (void)ctx; return g_now; }

#define ACC_SERIES 117

static size_t pass(char *b, size_t cap, long long t, int k) {
    size_t o = 0;
#define ADD(...) do { int w_ = snprintf(b + o, cap - o, __VA_ARGS__); \
                      if (w_ > 0 && (size_t)w_ < cap - o) o += (size_t)w_; } while (0)
    for (int i = 0; i < 15; i++)
        ADD("{\"type\":\"connections\",\"ts\":%lld,\"src\":\"10.0.0.%d:5%04d\","
            "\"dst\":\"93.184.216.%d:443\",\"proto\":\"tcp\",\"state\":\"ESTABLISHED\","
            "\"retx\":0,\"rx_bytes\":%d,\"tx_bytes\":%d}\n", t, i + 1, i, i, k * 10, k);
    ADD("{\"type\":\"iface\",\"ts\":%lld,\"name\":\"lo\",\"rx_bytes\":1,\"tx_bytes\":1,"
        "\"rx_rate\":%d.25,\"tx_rate\":%d.25,\"mtu\":65536}\n", t, k % 7, k % 7);
    ADD("{\"type\":\"iface\",\"ts\":%lld,\"name\":\"eth0\",\"rx_bytes\":%d,"
        "\"tx_bytes\":%d,\"rx_rate\":%d.50,\"tx_rate\":%d.75,\"mtu\":1500}\n",
        t, k * 1000, k * 100, 1000 + k % 13, 100 + k % 5);
    for (int i = 0; i < 20; i++)
        ADD("{\"type\":\"top_host\",\"ts\":%lld,\"ip\":\"10.0.0.%d\",\"hostname\":"
            "\"host%d.lan\",\"owner\":\"\",\"first_seen\":%lld,\"last_seen\":%lld,"
            "\"conn_count\":%d,\"rx_rate\":%d.00,\"tx_rate\":%d.00,\"rx_bytes\":1,"
            "\"tx_bytes\":1}\n", t, i + 1, i, T - 50, t, i % 4, i * 10, i);
    for (int i = 0; i < 30; i++)
        ADD("{\"type\":\"device\",\"ts\":%lld,\"mac\":\"02:00:00:00:00:%02x\","
            "\"ip\":\"10.0.0.%d\",\"hostname\":\"\",\"vendor\":\"\",\"last_ssid\":\"\","
            "\"is_ap\":0,\"signal_dbm\":-50,\"probe_count\":0,\"sources\":1,"
            "\"last_seen\":%lld,\"risk\":\"none\"}\n", t, i + 1, i + 1, t);
    ADD("{\"type\":\"dns\",\"ts\":%lld,\"src\":\"10.0.0.%d\",\"qname\":\"q%d.example\","
        "\"qtype\":\"A\",\"answer\":\"\",\"is_resp\":0}\n", t, 1 + k % 5, k);
    for (int i = 0; i < 10; i++)
        ADD("{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":\"02:00:00:00:00:%02x\","
            "\"ssid\":\"home\",\"signal_dbm\":-60,\"channel\":6,\"first_seen\":%lld,"
            "\"last_seen\":%lld,\"frame_count\":%d,\"flood\":0}\n",
            t, i + 1, T - 100, t, k);
    static const int ch[3] = { 1, 6, 11 };
    for (int i = 0; i < 3; i++)
        ADD("{\"type\":\"channel_summary\",\"ts\":%lld,\"channel\":%d,\"band\":"
            "\"2.4 GHz\",\"ap_count\":%d,\"assoc_count\":1,\"best_signal\":-40,"
            "\"top_ssid\":\"home\",\"ctrl_total\":%d,\"last_seen\":%lld}\n",
            t, ch[i], 2 + i, k * 10, t);
    ADD("{\"type\":\"sensor_health\",\"ts\":%lld,\"capture_open\":1}\n", t);
#undef ADD
    return o;
}

static web_feed_t g_feed;
static web_live_t g_live;

static void test_acceptance_one_hour(void) {
    char dir[64] = "/tmp/slothweb-hour-XXXXXX";
    WT_ASSERT(mkdtemp(dir) != NULL);
    char p[128], wal[160], shm[160], err[512];
    snprintf(p, sizeof(p), "%s/slothweb.db", dir);
    snprintf(wal, sizeof(wal), "%s-wal", p);
    snprintf(shm, sizeof(shm), "%s-shm", p);
    static web_store_t st;
    static web_metrics_t mx;
    int have = web_store_available();
    if (have) WT_EQ(web_store_open(&st, p, err, sizeof(err)), 0);
    char e2[64];
    WT_EQ(web_rollup_init(&ru, WEB_DEFAULT_MAX_KEYS, have, e2, sizeof(e2)), 0);
    g_now = T;
    WT_EQ(web_metrics_init(&mx, &ru, pinned, NULL), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, have ? &st : NULL, WEB_DEFAULT_RETAIN_DAYS,
                        WEB_DEFAULT_MAX_MB, pinned, NULL), 0);
    web_live_init(&g_live, "unix:/test/sloth.sock");
    web_feed_reset(&g_feed);
    g_feed.metrics = &mx;

    static char buf[64 * 1024];
    /* The largest the store got on disk, WAL and shm included, after
     * every step: the hour mark's compaction truncates the WAL, so a
     * size taken only after it says nothing about the hour before. */
    long long max_disk = 0;
    int max_at = -1;
    for (int s = 0; s <= 3600; s++) {
        g_now = T + s;
        if (s % 2 == 0 && s < 3600) {
            size_t n = pass(buf, sizeof(buf), g_now, s / 2);
            web_feed_bytes(&g_feed, &g_live, buf, n, (long long)s * 1000);
        }
        /* At s = 3600, the hour mark: every bucket of the hour is due,
         * written, and the hourly compaction has run after the write. */
        web_tsdb_step(&ts, g_now);
        if (have) {
            struct stat sb;
            long long b = 0;
            if (stat(p, &sb) == 0) b += sb.st_size;
            if (stat(wal, &sb) == 0) b += sb.st_size;
            if (stat(shm, &sb) == 0) b += sb.st_size;
            if (b > max_disk) { max_disk = b; max_at = s; }
        }
    }
    web_rollup_stats_t rs;
    web_rollup_stats(&ru, &rs);
    WT_EQ(rs.series, ACC_SERIES);
    WT_EQ(rs.queue_rows, 0);
    WT_EQ(rs.q_dropped, 0);
    WT_EQ(rs.rows_closed[WEB_TIER_FINE], ACC_SERIES * 360);
    WT_EQ(rs.rows_closed[WEB_TIER_MINUTE], ACC_SERIES * 60);
    WT_EQ(rs.rows_closed[WEB_TIER_HOUR], ACC_SERIES);
    WT_EQ(rs.evictions[WEB_KC_DEV] + rs.evictions[WEB_KC_HOST], 0);
    WT_EQ(g_live.decode_errors, 0);

    if (have) {
        WT_EQ(web_store_count(&st, WEB_TIER_FINE), ACC_SERIES * 360);
        WT_EQ(web_store_count(&st, WEB_TIER_MINUTE), ACC_SERIES * 60);
        WT_EQ(web_store_count(&st, WEB_TIER_HOUR), ACC_SERIES);
        web_store_stats_t ss;
        web_store_stats(&st, &ss);
        WT_EQ(ss.write_errors, 0);
        WT_EQ(ss.compactions, 2);              /* at start, and at the hour */
        WT_EQ(ss.rows[WEB_TIER_FINE], ACC_SERIES * 360);
    }

    /* The 24 h chart's request, as the page makes it. */
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.tsdb = &ts;
    h.wall_s = g_now;
    char rq[256];
    snprintf(rq, sizeof(rq), "GET /api/series?metric=iface.rx_rate&key=eth0&tier=fine"
             "&from=%lld&to=%lld HTTP/1.1\r\nHost: 127.0.0.1:8770\r\n\r\n",
             g_now - 86400, g_now);
    web_resp_t r = route(&h, rq, out, sizeof(out));
    WT_EQ(r.status, 200);
    WT_HAS(out, "\"step\":10,");
    WT_HAS(out, "\"more\":false,");
    WT_HAS(out, have ? "\"source\":\"store+memory\"" : "\"source\":\"memory\"");
    /* 360 points, 10 s apart, T .. T+3590: the last hour at 10 s. */
    const char *pt = strstr(out, "\"points\":[");
    WT_ASSERT(pt != NULL);
    int count = 0, gaps = 0;
    long long prev = -1, first = -1;
    for (const char *q = pt ? pt + 10 : NULL; q && (q = strchr(q, '[')); q++) {
        long long t = atoll(q + 1);
        if (first < 0) first = t;
        if (prev >= 0 && t - prev != 10) gaps++;
        prev = t;
        count++;
    }
    WT_EQ(count, 360);
    WT_EQ(gaps, 0);
    WT_EQ(first, T);
    WT_EQ(prev, T + 3590);
    /* And the gauge's mean is the mean of the bucket's five passes. */
    char want[64];
    snprintf(want, sizeof(want), "[%lld,1002.5,1000.5,1004.5,5]", T);
    WT_HAS(out, want);

    if (have) {
        /* The store stayed under 5 MB on disk, its WAL included, all
         * hour long. Seen red with wal_autocheckpoint=0 and
         * journal_size_limit=-1 in web_store_open(): 143,163,896 bytes
         * at second 3590, while the size after the hour mark alone
         * (2,027,520) stayed under 5 MB. */
        struct stat sb;
        long long bytes = 0;
        if (stat(p, &sb) == 0) bytes += sb.st_size;
        if (stat(wal, &sb) == 0) bytes += sb.st_size;
        if (stat(shm, &sb) == 0) bytes += sb.st_size;
        fprintf(stderr, "  one hour: %d fine rows, %lld bytes on disk after "
                "the hour's compaction, at most %lld (second %d)\n",
                ACC_SERIES * 360, bytes, max_disk, max_at);
        WT_ASSERT(bytes > 0);
        WT_ASSERT(max_disk >= bytes);
        WT_ASSERT(max_disk < 5LL * 1024 * 1024);
        /* The 24 h answer above is all in memory still (the ring holds
         * the hour): the store's fine tier must answer it too, as it
         * does once the ring has moved on or after a restart. */
        static web_point_t sp[901];
        int more = 0;
        int sn = web_store_query(&st, WEB_TIER_FINE, WM_IFACE_RX, "eth0",
                                 g_now - 86400, g_now, sp, 900, &more);
        WT_EQ(sn, 360);
        WT_EQ(more, 0);
        int sgaps = 0;
        for (int i = 1; i < sn; i++) if (sp[i - 1].t - sp[i].t != 10) sgaps++;
        WT_EQ(sgaps, 0);
        if (sn == 360) {
            WT_EQ(sp[0].t, T + 3590);           /* newest first */
            WT_EQ(sp[359].t, T);
            WT_EQ(sp[359].n, 5);
            WT_ASSERT(sp[359].sum == 5012.5 && sp[359].min == 1000.5 &&
                      sp[359].max == 1004.5);
        }
        /* The minute tier answers too. */
        snprintf(rq, sizeof(rq), "GET /api/series?metric=conns.total&tier=minute"
                 "&from=%lld&to=%lld HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                 g_now - 86400, g_now);
        r = route(&h, rq, out, sizeof(out));
        WT_EQ(r.status, 200);
        snprintf(want, sizeof(want), "[%lld,15,15,15,30]", T + 3540);
        WT_HAS(out, want);

        /* And through /api/series with nothing in memory: a restart over
         * the same store, a new rollup with an empty ring, the same 24 h
         * request answered from the store alone. Seen red with
         * web_series.c reading the store for the minute and hour tiers
         * only (0 points). */
        web_tsdb_destroy(&ts);
        web_rollup_destroy(&ru);
        WT_EQ(web_rollup_init(&ru, WEB_DEFAULT_MAX_KEYS, 1, e2, sizeof(e2)), 0);
        WT_EQ(web_tsdb_init(&ts, &ru, &st, WEB_DEFAULT_RETAIN_DAYS,
                            WEB_DEFAULT_MAX_MB, pinned, NULL), 0);
        snprintf(rq, sizeof(rq), "GET /api/series?metric=iface.rx_rate&key=eth0"
                 "&tier=fine&from=%lld&to=%lld HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                 g_now - 86400, g_now);
        r = route(&h, rq, out, sizeof(out));
        WT_EQ(r.status, 200);
        WT_HAS(out, "\"source\":\"store+memory\"");
        pt = strstr(out, "\"points\":[");
        WT_ASSERT(pt != NULL);
        count = 0;
        for (const char *q = pt ? pt + 10 : NULL; q && (q = strchr(q, '[')); q++)
            count++;
        WT_EQ(count, 360);
        snprintf(want, sizeof(want), "[%lld,1002.5,1000.5,1004.5,5]", T);
        WT_HAS(out, want);
    }

    web_live_destroy(&g_live);
    web_tsdb_destroy(&ts);
    web_metrics_destroy(&mx);
    web_rollup_destroy(&ru);
    if (have) web_store_close(&st);
    unlink(p);
    unlink(wal);
    unlink(shm);
    rmdir(dir);
}

/* The store thread for real, beside the "HTTP" reads and the "ingest"
 * writes of this thread: what TSan needs to see the locks. The clock is
 * pinned (behind its own mutex, since two threads read it) and moved on
 * by this thread, ten simulated seconds per step. */
static pthread_mutex_t g_cmu = PTHREAD_MUTEX_INITIALIZER;
static long long g_ct;
static long long locked_clock(void *ctx) {
    (void)ctx;
    pthread_mutex_lock(&g_cmu);
    long long v = g_ct;
    pthread_mutex_unlock(&g_cmu);
    return v;
}

static void test_store_thread(void) {
    char dir[64] = "/tmp/slothweb-thread-XXXXXX";
    WT_ASSERT(mkdtemp(dir) != NULL);
    char p[128], s2[160], err[512], e2[64];
    snprintf(p, sizeof(p), "%s/t.db", dir);
    static web_store_t st;
    int have = web_store_available();
    if (have) WT_EQ(web_store_open(&st, p, err, sizeof(err)), 0);
    WT_EQ(web_rollup_init(&ru, 64, have, e2, sizeof(e2)), 0);
    g_ct = T;
    WT_EQ(web_tsdb_init(&ts, &ru, have ? &st : NULL, 30, 256, locked_clock, NULL), 0);
    WT_EQ(web_tsdb_start(&ts, err, sizeof(err)), 0);
    web_series_q_t q;
    char why[48];
    for (int i = 0; i < 150; i++) {
        long long now = locked_clock(NULL);
        web_rollup_add(&ru, WM_HOST_RX, "10.0.0.1", i, now);
        web_rollup_add(&ru, WM_CONNS_TOTAL, "", i, now);
        if (i % 10 == 0) {
            WT_EQ(parse("metric=host.rx_rate&key=10.0.0.1", now, have, &q, why), 0);
            WT_ASSERT(web_series_json(&ts, &q, body, sizeof(body)) > 0);
            web_rollup_stats_t rs;
            web_rollup_stats(&ru, &rs);
            if (have) {
                web_store_stats_t ss;
                web_store_stats(&st, &ss);
            }
        }
        pthread_mutex_lock(&g_cmu);
        g_ct += 10;
        pthread_mutex_unlock(&g_cmu);
        usleep(10000);
    }
    web_tsdb_stop(&ts);
    web_rollup_stats_t rs;
    web_rollup_stats(&ru, &rs);
    WT_EQ(rs.ring_rows, 2 * 150);
    WT_EQ(rs.queue_rows, 0);
    if (have) WT_EQ(web_store_count(&st, WEB_TIER_FINE), 2 * 150);
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    if (have) web_store_close(&st);
    unlink(p);
    snprintf(s2, sizeof(s2), "%s-wal", p); unlink(s2);
    snprintf(s2, sizeof(s2), "%s-shm", p); unlink(s2);
    rmdir(dir);
}

void run_series_tests(void) {
    WT_RUN(test_parameters_validated);
    WT_RUN(test_series_json_and_paging);
    WT_RUN(test_routes);
#ifdef WITH_SQLITE
    WT_RUN(test_worst_case_fits);
    WT_RUN(test_merged_answer_capped);
    WT_RUN(test_queue_high_water_flushes_early);
    WT_RUN(test_flush_all_writes_backlog_first);
#endif
    WT_RUN(test_acceptance_one_hour);
    WT_RUN(test_store_thread);
}
