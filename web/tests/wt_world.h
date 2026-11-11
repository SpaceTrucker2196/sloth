/* The world test_subnotes.c and test_mcp.c share: test_notes.c's (a
 * store in a fresh directory, the demo's sloth.db and stream, an
 * anomaly engine whose episodes the test places itself) with the GNSS,
 * ADS-B and APRS panels attached and fed one row each, so every kind
 * of note subject has something held. Each helper is static inline, so
 * a file using only some of them builds without a warning; the state
 * is one static per translation unit. */
#ifndef SLOTHWEB_WT_WORLD_H
#define SLOTHWEB_WT_WORLD_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_adsb.h"
#include "web_anomaly.h"
#include "web_aprs.h"
#include "web_baseline.h"
#include "web_frrs.h"
#include "web_frrs_int.h"
#include "web_gnss.h"
#include "web_ingest.h"
#include "web_live.h"
#include "web_notes.h"
#include "web_routes.h"
#include "web_server.h"
#include "web_ssidview.h"
#include "wt_tmp.h"
#include "wtest.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

#define W_T    SDB_NOW
#define W_MAC1 "02:de:00:00:00:16"          /* a demo device (192.0.2.16) */
#define W_MAC2 "02:de:00:00:00:99"          /* no device anywhere */
#define W_BLE1 "02:de:00:00:00:b1"          /* a BLE advertiser the world feeds */
#define W_HEX  "a1b2c3"                     /* an aircraft the world feeds */
#define W_CALL "N0TEST-5"                   /* an APRS station the world feeds */
#define W_SAT  "0.5"                        /* GPS PRN 5, fed */

int    demo_make_db(const char *path, long long now);
size_t demo_pass(long long t, long long start, unsigned long k, char *out, size_t cap);

typedef struct {
    char           dir[TEST_TMP_MAX];
    char           store_path[TEST_TMP_MAX + 32];
    char           sdb_path[TEST_TMP_MAX + 32];
    web_store_t    store;
    int            have_store, have_db;
    web_frrs_t     f;
    web_live_t     live;
    web_slothdb_t  sdb;
    web_baseline_t bl;
    web_anomaly_t  an;
    web_gnss_t     gnss;
    web_adsb_t     adsb;
    web_aprs_t     aprs;
    web_m4_t       m4;
    web_health_t   h;
} w_env_t;
static w_env_t W;
static char w_out[262144];

static inline const char *w_body(void) {
    const char *sep = strstr(w_out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static inline int w_count(const char *s, const char *w) {
    int n = 0;
    for (const char *q = strstr(s, w); q; q = strstr(q + 1, w)) n++;
    return n;
}

static inline void w_line(const char *line, void (*fn)(const web_jrec_t *)) {
    web_jrec_t *r = malloc(sizeof(*r));
    WT_ASSERT(r && web_jl_parse(line, strlen(line), r) == WEB_JL_OK);
    if (r) fn(r);
    free(r);
}
static inline void w_to_frrs(const web_jrec_t *r) { web_frrs_record(&W.f, r); }
static inline void w_to_gnss(const web_jrec_t *r) { web_gnss_record(&W.gnss, r, 1000); }
static inline void w_to_adsb(const web_jrec_t *r) { web_adsb_record(&W.adsb, r, 1000); }
static inline void w_to_aprs(const web_jrec_t *r) { web_aprs_record(&W.aprs, r, 1000); }

/* One BLE advertiser into the ledger, its name whatever the test says
 * (a hostile one included: the caller escapes it for JSON). */
static inline void w_ble_heard(const char *addr, int type, const char *name_json) {
    char line[1024];
    snprintf(line, sizeof(line), "{\"type\":\"ble_device\",\"ts\":%lld,\"addr\":\"%s\","
             "\"addr_type\":%d,\"iface\":\"bluetooth-monitor\",\"name\":\"%s\",\"has_rssi\":1,"
             "\"rssi\":-60,\"rssi_best\":-60,\"last_seen\":%lld}", (long long)W_T, addr, type,
             name_json, (long long)W_T);
    w_line(line, w_to_frrs);
}

static inline void w_store_up(int writes) {
    char err[512];
    if (web_store_available()) {
        WT_EQ(web_store_open(&W.store, W.store_path, err, sizeof(err)), 0);
        W.have_store = 1;
    }
    WT_EQ(web_frrs_init(&W.f, W.have_store ? &W.store : NULL, NULL, writes, err, sizeof(err)), 0);
    W.m4.frrs = &W.f;
}

static inline void w_open(int writes) {
    memset(&W, 0, sizeof(W));
    snprintf(W.dir, sizeof(W.dir), "%s/slothweb-world-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(W.dir) != NULL);
    snprintf(W.store_path, sizeof(W.store_path), "%s/slothweb.db", W.dir);
    snprintf(W.sdb_path, sizeof(W.sdb_path), "%s/sloth.db", W.dir);
    w_store_up(writes);
    web_live_init(&W.live, "unix:/demo/sloth.sock");
    web_live_sock_connected(&W.live, 0);
    W.have_db = web_store_available() && demo_make_db(W.sdb_path, W_T) == 0;
    web_sdb_fns_t fns = { NULL, NULL, NULL, &W.live };
    web_slothdb_init(&W.sdb, W.have_db ? W.sdb_path : "", &fns);
    W.m4.sdb = W.have_db ? &W.sdb : NULL;
    WT_EQ(web_baseline_init(&W.bl, 16), 0);
    web_anom_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.bl = &W.bl;
    c.max_keys = 64;
    WT_EQ(web_anomaly_init(&W.an, 64, &c), 0);
    W.m4.anomaly = &W.an;
    W.h.anomaly = &W.an;
    WT_EQ(web_gnss_init(&W.gnss), 0);
    WT_EQ(web_adsb_init(&W.adsb), 0);
    WT_EQ(web_aprs_init(&W.aprs), 0);
    W.m4.gnss = &W.gnss;
    W.m4.adsb = &W.adsb;
    W.m4.aprs = &W.aprs;
    W.h.gnss = &W.gnss;
    W.h.adsb = &W.adsb;
    W.h.aprs = &W.aprs;
    web_feed_t *fd = calloc(1, sizeof(*fd));
    static char buf[1 << 16];
    WT_ASSERT(fd != NULL);
    if (fd) {
        web_feed_reset(fd);
        fd->frrs = &W.f;
        long long start = W_T - 100;
        for (unsigned long k = 0; k < 20; k++) {
            size_t n = demo_pass(start + (long long)k, start, k, buf, sizeof(buf));
            web_feed_bytes(fd, &W.live, buf, n, (long long)k * 1000 + 500);
        }
        free(fd);
    }
    char line[640];
    w_ble_heard(W_BLE1, 1, "BLENAME-MARK");
    snprintf(line, sizeof(line), "{\"type\":\"gnss_sat\",\"ts\":%lld,\"gnss\":\"GPS\",\"gnssid\":0,"
             "\"svid\":5,\"prn\":5,\"sigid\":0,\"el\":45,\"az\":120,\"cn0\":41.0,\"used\":1,"
             "\"health\":1,\"sky_ts\":%lld}", (long long)W_T, (long long)W_T);
    w_line(line, w_to_gnss);
    snprintf(line, sizeof(line), "{\"type\":\"adsb_aircraft\",\"ts\":%lld,\"hex\":\"" W_HEX "\","
             "\"non_icao\":0,\"state\":\"live\",\"flight\":\"FLT-MARK\",\"first_seen\":%lld,"
             "\"last_seen\":%lld}", (long long)W_T, (long long)W_T - 60, (long long)W_T);
    w_line(line, w_to_adsb);
    snprintf(line, sizeof(line), "{\"type\":\"aprs_station\",\"ts\":%lld,\"call\":\"" W_CALL "\","
             "\"state\":\"live\",\"src\":\"file:/var/lib/direwolf/aprs.log\",\"first_seen\":%lld,"
             "\"last_seen\":%lld,\"packets\":1,\"via\":\"" W_CALL "\",\"direct\":1,"
             "\"heard_direct\":1,\"level\":50,\"best_level\":50,\"dti\":\"!\",\"symbol\":\"/#\","
             "\"comment\":\"APRS-COMMENT-MARK\"}", (long long)W_T, (long long)W_T - 60,
             (long long)W_T);
    w_line(line, w_to_aprs);
    W.h.wall_s = W_T;
    W.h.now_ms = 30000;
    W.h.m4 = &W.m4;
    W.h.live = &W.live;
}

static inline void w_close(void) {
    web_gnss_destroy(&W.gnss);
    web_adsb_destroy(&W.adsb);
    web_aprs_destroy(&W.aprs);
    web_anomaly_destroy(&W.an);
    web_baseline_destroy(&W.bl);
    web_frrs_destroy(&W.f);
    web_slothdb_destroy(&W.sdb);
    web_live_destroy(&W.live);
    web_store_close(&W.store);
    test_rm_tree(W.dir);
}

/* One episode in the engine, as a restore hands it one, and its id. */
static inline void w_ep(long long id, const char *rule, int metric, const char *key,
                        long long first, long long last, char *tid) {
    web_store_ep_t e;
    memset(&e, 0, sizeof(e));
    e.id = id;
    snprintf(e.kind, sizeof(e.kind), "%s", rule);
    e.metric = metric;
    snprintf(e.key, sizeof(e.key), "%s", key);
    e.state = WEB_EP_OPEN;
    e.score = e.peak = 70;
    snprintf(e.evidence, sizeof(e.evidence), "EVMARK evidence line");
    e.first_seen = first;
    e.last_seen = last;
    e.last_bucket = last;
    web_anomaly_restore_episode(&W.an, &e);
    if (tid) {
        int ri = -1;
        for (int i = 0; i < WEB_ANOM_RULE_COUNT; i++) if (!strcmp(web_anomaly_rule(i), rule)) ri = i;
        web_anomaly_tid(ri, metric, key, tid);
    }
}

/* ── in process: the router, as the server calls it ────────────────── */

static inline void w_rq(web_req_t *rq, const char *path, const char *query) {
    memset(rq, 0, sizeof(*rq));
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query ? query : "");
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    rq->content_length = -1;
}

static inline int w_route(const web_req_t *rq) {
    web_resp_t r;
    memset(&r, 0, sizeof(r));
    if (web_route(rq, &W.h, 1, w_out, sizeof(w_out), &r) != 0) return -1;
    size_t n = r.out_len < sizeof(w_out) - 1 ? r.out_len : sizeof(w_out) - 1;
    if (r.body && r.body_len && n + r.body_len < sizeof(w_out) - 1) {
        memcpy(w_out + n, r.body, r.body_len);
        n += r.body_len;
    }
    w_out[n] = '\0';
    if (r.body_owned) free(r.body_owned);
    else if (r.body_free) free((void *)r.body);
    return r.status;
}

static inline int w_get(const char *path, const char *query) {
    web_req_t rq;
    w_rq(&rq, path, query);
    return w_route(&rq);
}

/* A browser's POST: the page's own Origin unless the test gives
 * another (NULL: none). Two seconds apart, one token's refill. */
static inline int w_post_h(const char *path, const char *body, const char *origin,
                           const char *ctype) {
    web_req_t rq;
    w_rq(&rq, path, "");
    rq.is_post = 1;
    if (origin) { snprintf(rq.origin, sizeof(rq.origin), "%s", origin); rq.origin_count = 1; }
    if (ctype) { snprintf(rq.ctype, sizeof(rq.ctype), "%s", ctype); rq.ctype_count = 1; }
    rq.body = body;
    rq.body_len = strlen(body);
    rq.content_length = (long long)rq.body_len;
    W.h.now_ms += 2000;
    snprintf(rq.peer, sizeof(rq.peer), "127.0.0.1");
    return w_route(&rq);
}

static inline int w_post(const char *path, const char *body) {
    return w_post_h(path, body, "http://127.0.0.1:8770", "application/json");
}

/* The id of the first /api/alerts row of a type, into out. */
static inline int w_alert_id(const char *type, char *out, size_t cap) {
    out[0] = '\0';
    if (w_get("/api/alerts", "limit=100") != 200) return 0;
    char want[80];
    snprintf(want, sizeof(want), "\"type_name\":\"%s\"", type);
    const char *b = w_body(), *t = strstr(b, want);
    if (!t) return 0;
    const char *id = NULL;
    for (const char *p = strstr(b, "{\"id\":\""); p && p < t; p = strstr(p + 1, "{\"id\":\"")) id = p + 7;
    if (!id) return 0;
    const char *e = strchr(id, '"');
    if (!e || (size_t)(e - id) >= cap) return 0;
    memcpy(out, id, (size_t)(e - id));
    out[e - id] = '\0';
    return 1;
}

/* The route's parameter for an SSID's octets. */
static inline const char *w_ssid_id(const char *octets) {
    static char id[48];
    web_ssid_param_of(octets, strlen(octets), id);
    return id;
}

#ifdef WITH_SQLITE
static inline long long w_store_int(const char *sql) {
    sqlite3 *db = NULL;
    long long v = -1;
    sqlite3_stmt *s = NULL;
    if (sqlite3_open(W.store_path, &db) == SQLITE_OK &&
        sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW)
        v = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    sqlite3_close(db);
    return v;
}

static inline int w_file_has(const char *path, const char *needle) {
    static unsigned char buf[1 << 22];
    size_t n = sdb_slurp(path, buf, sizeof(buf));
    size_t nl = strlen(needle);
    for (size_t i = 0; n >= nl && i + nl <= n; i++)
        if (!memcmp(buf + i, needle, nl)) return 1;
    return 0;
}

/* Does the store's file, or its WAL, hold these bytes? */
static inline int w_store_has(const char *needle) {
    char w[TEST_TMP_MAX + 48];
    snprintf(w, sizeof(w), "%s-wal", W.store_path);
    return w_file_has(W.store_path, needle) || w_file_has(w, needle);
}
#endif

/* ── over real sockets ─────────────────────────────────────────────── */

typedef struct {
    web_server_t *s;
    pthread_t     th;
    int           rc;
} w_running_t;

static inline void *w_server_main(void *arg) {
    w_running_t *r = arg;
    r->rc = web_server_run(r->s);
    return NULL;
}

/* The server on an ephemeral loopback port over the world; c is the
 * configuration the caller made (web_config_defaults() and its own
 * flags), its port and timeouts set here. */
static inline int w_srv_start(w_running_t *r, web_config_t *c) {
    c->bind_port = 0;
    c->timeout_ms = 2000;
    c->linger_ms = 200;
    char err[256];
    r->s = calloc(1, sizeof(*r->s));
    if (!r->s || web_server_open(r->s, c, err, sizeof(err)) != 0) {
        if (r->s) web_server_close(r->s);
        free(r->s);
        r->s = NULL;
        return -1;
    }
    web_server_set_live(r->s, &W.live);
    web_server_set_anomaly(r->s, &W.an);
    web_server_set_m4(r->s, &W.m4);
    web_server_set_gnss(r->s, &W.gnss);
    web_server_set_adsb(r->s, &W.adsb);
    web_server_set_aprs(r->s, &W.aprs);
    if (pthread_create(&r->th, NULL, w_server_main, r) != 0) return -1;
    return 0;
}

static inline void w_srv_stop(w_running_t *r) {
    web_server_stop(r->s);
    pthread_join(r->th, NULL);
    web_server_close(r->s);
    free(r->s);
    r->s = NULL;
}

/* One request sent whole and the answer read to the close, into w_out. */
static inline void w_exchange(uint16_t port, const char *req, size_t len) {
    w_out[0] = '\0';
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct timeval tv = { 4, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
        send(fd, req, len, MSG_NOSIGNAL);
        size_t n = 0;
        while (n + 1 < sizeof(w_out)) {
            ssize_t g = recv(fd, w_out + n, sizeof(w_out) - 1 - n, 0);
            if (g <= 0) break;
            n += (size_t)g;
        }
        w_out[n] = '\0';
    }
    close(fd);
}

#endif
