/* Triage notes on anomalies and the links between findings
 * (web_relate.c, web_frrs.c; owner request 2026-11-11): the alert
 * triage tests of test_frrs.c again, one for one, on an anomaly's id,
 * then the links and the candidates. The same world as test_frrs.c (a
 * store in a fresh directory, the demo's sloth.db and stream) with an
 * anomaly engine whose episodes the test places itself
 * (web_anomaly_restore_episode()), so "the engine forgot it" and "it
 * was detected again" are a new engine with other episodes.
 *
 * Every absence assertion here was seen red under the mutation its
 * comment names, in this tree, the source restored and the suite run
 * green again afterwards. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_anomaly.h"
#include "web_assets.h"
#include "web_baseline.h"
#include "web_frrs.h"
#include "web_frrs_int.h"
#include "web_ingest.h"
#include "web_live.h"
#include "web_routes.h"
#include "web_server.h"
#include "wt_tmp.h"
#include "wtest.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

#define T SDB_NOW
#define MAC1 "02:de:00:00:00:16"          /* a demo device (192.0.2.16) */
#define MAC2 "02:de:00:00:00:99"          /* no device anywhere */
#define MAC3 "02:de:00:00:00:12"          /* another demo device */
#define BLE1 "02:de:00:00:00:b1"          /* a BLE advertiser the test feeds */
#define KARMA "06:de:00:00:00:a4"         /* the demo's KARMA_AP names it */

int    demo_make_db(const char *path, long long now);
size_t demo_pass(long long t, long long start, unsigned long k, char *out, size_t cap);

static char g_out[262144];

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

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
    web_m4_t       m4;
    web_health_t   h;
} env_t;
static env_t E;

static void an_open(void) {
    web_anom_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.bl = &E.bl;
    c.max_keys = 64;
    WT_EQ(web_anomaly_init(&E.an, 64, &c), 0);
    E.m4.anomaly = &E.an;
    E.h.anomaly = &E.an;
}

#ifdef WITH_SQLITE
/* A new engine: every episode forgotten, as after a day or a restart
 * with nothing saved. */
static void an_reset(void) {
    web_anomaly_destroy(&E.an);
    an_open();
}

#endif

static void store_up(int writes) {
    char err[512];
    if (web_store_available()) {
        WT_EQ(web_store_open(&E.store, E.store_path, err, sizeof(err)), 0);
        E.have_store = 1;
    }
    WT_EQ(web_frrs_init(&E.f, E.have_store ? &E.store : NULL, NULL, writes, err, sizeof(err)), 0);
    E.m4.frrs = &E.f;
}

#ifdef WITH_SQLITE
static void store_down(void) {
    web_frrs_destroy(&E.f);
    web_store_close(&E.store);
    memset(&E.f, 0, sizeof(E.f));
    memset(&E.store, 0, sizeof(E.store));
}

#endif

static void env_open(int writes) {
    memset(&E, 0, sizeof(E));
    snprintf(E.dir, sizeof(E.dir), "%s/slothweb-notes-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(E.dir) != NULL);
    snprintf(E.store_path, sizeof(E.store_path), "%s/slothweb.db", E.dir);
    snprintf(E.sdb_path, sizeof(E.sdb_path), "%s/sloth.db", E.dir);
    store_up(writes);
    web_live_init(&E.live, "unix:/demo/sloth.sock");
    web_live_sock_connected(&E.live, 0);
    E.have_db = web_store_available() && demo_make_db(E.sdb_path, T) == 0;
    web_sdb_fns_t fns = { NULL, NULL, NULL, &E.live };
    web_slothdb_init(&E.sdb, E.have_db ? E.sdb_path : "", &fns);
    E.m4.sdb = E.have_db ? &E.sdb : NULL;
    WT_EQ(web_baseline_init(&E.bl, 16), 0);
    an_open();
    web_feed_t *fd = calloc(1, sizeof(*fd));
    static char buf[1 << 16];
    WT_ASSERT(fd != NULL);
    if (fd) {
        web_feed_reset(fd);
        fd->frrs = &E.f;
        long long start = T - 100;
        for (unsigned long k = 0; k < 20; k++) {
            size_t n = demo_pass(start + (long long)k, start, k, buf, sizeof(buf));
            web_feed_bytes(fd, &E.live, buf, n, (long long)k * 1000 + 500);
        }
        free(fd);
    }
    E.h.wall_s = T;
    E.h.now_ms = 30000;
    E.h.m4 = &E.m4;
    E.h.live = &E.live;
}

static void env_close(void) {
    web_anomaly_destroy(&E.an);
    web_baseline_destroy(&E.bl);
    web_frrs_destroy(&E.f);
    web_slothdb_destroy(&E.sdb);
    web_live_destroy(&E.live);
    web_store_close(&E.store);
    test_rm_tree(E.dir);
}

static void base_rq(web_req_t *rq, const char *path, const char *query) {
    memset(rq, 0, sizeof(*rq));
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query ? query : "");
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    rq->content_length = -1;
}

static int get(const char *path, const char *query) {
    web_req_t rq;
    web_resp_t r;
    base_rq(&rq, path, query);
    memset(&r, 0, sizeof(r));
    if (web_route(&rq, &E.h, 1, g_out, sizeof(g_out), &r) != 0) return -1;
    size_t n = r.out_len < sizeof(g_out) - 1 ? r.out_len : sizeof(g_out) - 1;
    if (r.body && r.body_len && n + r.body_len < sizeof(g_out) - 1) {
        memcpy(g_out + n, r.body, r.body_len);
        n += r.body_len;
    }
    g_out[n] = '\0';
    if (r.body_free) free((void *)r.body);
    /* /api/bundle's body is the route's heap copy, the caller's to free
     * (web_resp_t.body_owned); NULL for every other route here. */
    free(r.body_owned);
    return r.status;
}

static int post_h(const char *path, const char *body, const char *origin, const char *ctype) {
    web_req_t rq;
    web_resp_t r;
    base_rq(&rq, path, "");
    rq.is_post = 1;
    if (origin) { snprintf(rq.origin, sizeof(rq.origin), "%s", origin); rq.origin_count = 1; }
    if (ctype) { snprintf(rq.ctype, sizeof(rq.ctype), "%s", ctype); rq.ctype_count = 1; }
    rq.body = body;
    rq.body_len = strlen(body);
    rq.content_length = (long long)rq.body_len;
    /* Two seconds apart, one token's refill: the bucket is test_frrs.c's. */
    E.h.now_ms += 2000;
    snprintf(rq.peer, sizeof(rq.peer), "127.0.0.1");
    memset(&r, 0, sizeof(r));
    if (web_route(&rq, &E.h, 1, g_out, sizeof(g_out), &r) != 0) return -1;
    g_out[r.out_len < sizeof(g_out) ? r.out_len : sizeof(g_out) - 1] = '\0';
    return r.status;
}

static int post(const char *path, const char *body) {
    return post_h(path, body, "http://127.0.0.1:8770", "application/json");
}

/* POST /api/frrs/triage and /api/frrs/relate, the body from a format. */
static int triage(const char *id, const char *state, const char *note) {
    char b[1024];
    if (note) snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"%s\",\"note\":\"%s\",\"by\":\"op\"}", id, state, note);
    else snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"%s\"}", id, state);
    return post("/api/frrs/triage", b);
}
static int link_add(const char *from, const char *to, const char *note) {
    char b[1024];
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"from\":\"%s\",\"to\":\"%s\",\"note\":\"%s\"}", from, to,
             note ? note : "");
    return post("/api/frrs/relate", b);
}
static int related(const char *id) {
    char q[96];
    snprintf(q, sizeof(q), "id=%s", id);
    return get("/api/frrs/related", q);
}
static int history(const char *id) {
    char q[96];
    snprintf(q, sizeof(q), "id=%s", id);
    return get("/api/frrs/history", q);
}
static int states(const char *id) {
    char q[96];
    snprintf(q, sizeof(q), "ids=%s", id);
    return get("/api/frrs/states", q);
}

#ifdef WITH_SQLITE
/* The id of the first /api/alerts row of a type, into out. */
static int id_of(const char *type, char *out, size_t cap) {
    out[0] = '\0';
    if (get("/api/alerts", "limit=100") != 200) return 0;
    char want[80];
    snprintf(want, sizeof(want), "\"type_name\":\"%s\"", type);
    const char *b = body_of(g_out), *t = strstr(b, want);
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

#endif

#ifdef WITH_SQLITE
/* The first /api/alerts row only sloth.db holds (its id a rowid's, not
 * a stream handle), and its type's name. */
static int db_only_alert(char *id, size_t cap, char *type, size_t tcap) {
    id[0] = type[0] = '\0';
    if (get("/api/alerts", "limit=100&state=closed") != 200) return 0;
    const char *p = strstr(body_of(g_out), "{\"id\":\"d");
    if (!p) return 0;
    const char *e = strchr(p + 7, '"'), *t = strstr(p, "\"type_name\":\"");
    if (!e || !t || (size_t)(e - p - 7) >= cap) return 0;
    snprintf(id, cap, "%.*s", (int)(e - p - 7), p + 7);
    t += 13;
    const char *te = strchr(t, '"');
    if (!te || (size_t)(te - t) >= tcap) return 0;
    snprintf(type, tcap, "%.*s", (int)(te - t), t);
    return 1;
}

#endif

static long long json_int(const char *b, const char *key) {
    char k[64];
    snprintf(k, sizeof(k), "\"%s\":", key);
    const char *p = strstr(b, k);
    return p ? atoll(p + strlen(k)) : -1;
}

#ifdef WITH_SQLITE
static void json_str(const char *b, const char *key, char *out, size_t cap) {
    char k[64];
    snprintf(k, sizeof(k), "\"%s\":\"", key);
    const char *p = strstr(b, k);
    out[0] = '\0';
    if (!p) return;
    p += strlen(k);
    const char *e = strchr(p, '"');
    if (e && (size_t)(e - p) < cap) snprintf(out, cap, "%.*s", (int)(e - p), p);
}

#endif

static int count_of(const char *s, const char *w) {
    int n = 0;
    for (const char *q = strstr(s, w); q; q = strstr(q + 1, w)) n++;
    return n;
}

#ifdef WITH_SQLITE
/* The member of the answer from `from` to the next `to` (the links, or
 * the candidates), copied so a search stays inside it. */
static const char *part(const char *from, const char *to) {
    static char buf[65536];
    const char *a = strstr(body_of(g_out), from);
    const char *b = a ? strstr(a, to) : NULL;
    buf[0] = '\0';
    if (a && b && (size_t)(b - a) < sizeof(buf)) snprintf(buf, sizeof(buf), "%.*s", (int)(b - a), a);
    return buf;
}
static const char *links_part(void) { return part("\"links\":[", "],\"links_more\":"); }
static const char *suggest_part(void) { return part("\"suggest\":[", "],\"suggest_note\":"); }

/* An alert's label as a link keeps it: its type's name and the address
 * its descriptor names. */
static void alert_label(const char *id, const char *type, char *out, size_t cap) {
    char addr[64] = "";
    if (history(id) == 200) {
        const char *d = strstr(body_of(g_out), "\"descriptor\":");
        if (d) json_str(d, "addr", addr, sizeof(addr));
    }
    snprintf(out, cap, "%s%s%s", type, addr[0] ? " " : "", addr);
}

#endif

/* One episode in the engine, as a restore hands it one, and its id. */
static void ep(long long id, const char *rule, int metric, const char *key, int state,
               long long first, long long last, char *tid) {
    web_store_ep_t e;
    memset(&e, 0, sizeof(e));
    e.id = id;
    snprintf(e.kind, sizeof(e.kind), "%s", rule);
    e.metric = metric;
    snprintf(e.key, sizeof(e.key), "%s", key);
    e.state = state;
    e.score = e.peak = 70;
    snprintf(e.evidence, sizeof(e.evidence), "EVMARK evidence line");
    e.first_seen = first;
    e.last_seen = last;
    e.last_bucket = last;
    web_anomaly_restore_episode(&E.an, &e);
    if (tid) {
        int ri = -1;
        for (int i = 0; i < WEB_ANOM_RULE_COUNT; i++) if (!strcmp(web_anomaly_rule(i), rule)) ri = i;
        web_anomaly_tid(ri, metric, key, tid);
    }
}

#ifdef WITH_SQLITE
static int file_has(const char *path, const char *needle) {
    static unsigned char buf[1 << 22];
    size_t n = sdb_slurp(path, buf, sizeof(buf));
    size_t nl = strlen(needle);
    for (size_t i = 0; n >= nl && i + nl <= n; i++)
        if (!memcmp(buf + i, needle, nl)) return 1;
    return 0;
}
static int store_has(const char *needle) {
    char w[TEST_TMP_MAX + 48];
    snprintf(w, sizeof(w), "%s-wal", E.store_path);
    return file_has(E.store_path, needle) || file_has(w, needle);
}
static int sql_on(const char *path, const char *sql) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(path, &db);
    if (rc == SQLITE_OK) {
        sqlite3_busy_timeout(db, 2000);
        rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
    }
    sqlite3_close(db);
    return rc == SQLITE_OK ? 0 : -1;
}
static long long store_int(const char *sql) {
    sqlite3 *db = NULL;
    long long v = -1;
    sqlite3_stmt *s = NULL;
    if (sqlite3_open(E.store_path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW)
        v = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    sqlite3_close(db);
    return v;
}
#endif

/* ── triage, as test_frrs.c has it for an alert ─────────────────────── */

/* test_triage_round_trip's: a decision on an anomaly, its history, the
 * clear that undoes it (a second row, not a delete), and a note holding
 * markup kept as typed and served escaped. The row says which episode
 * it was made on. Without a store the write is 503 no_store and every
 * read still answers, as alert triage's do. */
static void test_anomaly_triage_round_trip(void) {
    env_open(1);
    char tid[WEB_ANOM_TID_MAX + 1], want[160];
    ep(1, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 600, T - 60, tid);
    /* The id the episode's own JSON carries is the one the routes take. */
    WT_EQ(get("/api/anomalies", ""), 200);
    snprintf(want, sizeof(want), "\"tid\":\"%s\"", tid);
    WT_HAS(g_out, want);
    WT_EQ(triage(tid, "noise", "the <b>printer</b>"), E.have_store ? 200 : 503);
    if (!E.have_store) {
        WT_HAS(g_out, "no_store");
        WT_EQ(states(tid), 200);
        WT_HAS(g_out, "\"store\":\"none\"");
        snprintf(want, sizeof(want), "\"untriaged\":[\"%s\"]", tid);
        WT_HAS(g_out, want);
        WT_HAS(g_out, "\"writes\":false");
        WT_EQ(history(tid), 200);
        WT_HAS(g_out, "\"anomaly\":{\"rule\":\"A3\",\"kind\":\"hours\",\"metric\":\"dev.present\"");
        WT_HAS(g_out, "\"current\":{\"state\":\"untriaged\",\"history_n\":0}");
        WT_EQ(related(tid), 200);
        WT_HAS(g_out, "\"store\":\"none\",\"writes\":false");
        WT_HAS(g_out, "\"links\":[]");
        WT_EQ(link_add(tid, MAC1, ""), 503);
        WT_HAS(g_out, "no_store");
        env_close();
        return;
    }
    WT_HAS(g_out, "\"state\":\"noise\"");
    WT_HAS(g_out, "the \\u003cb\\u003eprinter\\u003c/b\\u003e");
    WT_LACKS(body_of(g_out), "<b>");
    WT_HAS(g_out, "\"peer\":\"127.0.0.1\"");
    WT_HAS(g_out, "\"by\":\"op\"");
    snprintf(want, sizeof(want), "\"episode\":%lld,\"carried\":false", T - 600);
    WT_HAS(g_out, want);
    WT_EQ(states(tid), 200);
    WT_HAS(g_out, "\"state\":\"noise\"");
    WT_HAS(g_out, "\"types\":{}");                    /* no alert type: nothing to recommend */
    WT_EQ(triage(tid, "untriaged", NULL), 200);
    WT_HAS(g_out, "\"prev_state\":\"noise\"");
    WT_EQ(history(tid), 200);
    WT_EQ(count_of(body_of(g_out), "\"prev_state\":"), 3);   /* current + two rows */
    WT_HAS(g_out, "\"current\":{\"state\":\"untriaged\"");
    snprintf(want, sizeof(want), "\"anomaly\":{\"rule\":\"A3\",\"kind\":\"hours\",\"metric\":\"dev.present\","
             "\"key\":\"%s\",\"held\":true,\"open\":true,\"first_seen\":%lld", MAC1, T - 600);
    WT_HAS(g_out, want);
    WT_HAS(g_out, "\"recommend\":null");
#ifdef WITH_SQLITE
    WT_ASSERT(store_has("the <b>printer</b>"));      /* stored as typed */
    WT_EQ(store_int("SELECT COUNT(*) FROM anom_subject WHERE rule='A3' AND metric='dev.present'"
                    " AND key='" MAC1 "'"), 1);
#endif
    env_close();
}

/* test_known_is_triaged_out's and test_state_past_known_refused's: the
 * four decided states are an anomaly's too, nothing else is a state,
 * and "recommended" has nothing to follow (no assessment judges an
 * anomaly rule). */
static void test_anomaly_states(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char tid[WEB_ANOM_TID_MAX + 1], want[64];
    ep(1, "A7", WM_HOST_CONNS, "192.0.2.16", WEB_EP_OPEN, T - 600, T - 60, tid);
    static const char *const ST[] = { "false", "noise", "incident", "known" };
    for (size_t i = 0; i < 4; i++) {
        WT_EQ(triage(tid, ST[i], NULL), 200);
        snprintf(want, sizeof(want), "\"current\":{\"state\":\"%s\"", ST[i]);
        WT_HAS(g_out, want);
    }
    WT_EQ(triage(tid, "maybe", NULL), 400);
    WT_HAS(g_out, "bad_state");
    WT_EQ(triage(tid, "5", NULL), 400);
    WT_EQ(triage(tid, "recommended", NULL), 409);
    WT_HAS(g_out, "no_recommendation");
    WT_EQ(states(tid), 200);
    WT_HAS(g_out, "\"state\":\"known\"");
    env_close();
}

/* test_cross_origin_refused's, on an anomaly's triage and on a link:
 * each refusal leaves the store without a row. The guard is the alert
 * write's own (web_frrs_gate(), the same call for every POST path);
 * seen red with "/api/frrs/relate" answered before the gate in
 * web_frrs_route() (the evil.example link written, 200). */
static void test_anomaly_cross_origin_refused(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char tid[WEB_ANOM_TID_MAX + 1], b[256], l[256];
    ep(1, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 600, T - 60, tid);
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\"}", tid);
    snprintf(l, sizeof(l), "{\"op\":\"add\",\"from\":\"%s\",\"to\":\"" MAC1 "\"}", tid);
    static const char *const bad[] = {
        "http://evil.example", "http://127.0.0.1:8771", "https://127.0.0.1:8770", "null",
        "http://127.0.0.1:8770/", "http://user@127.0.0.1:8770",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        WT_EQ(post_h("/api/frrs/triage", b, bad[i], "application/json"), 403);
        WT_HAS(g_out, "bad_origin");
        WT_EQ(post_h("/api/frrs/relate", l, bad[i], "application/json"), 403);
        WT_HAS(g_out, "bad_origin");
    }
    WT_EQ(post_h("/api/frrs/triage", b, NULL, "application/json"), 403);
    WT_EQ(post_h("/api/frrs/relate", l, NULL, "application/json"), 403);
    /* Sec-Fetch-Site from another site. */
    {
        web_req_t rq;
        web_resp_t r;
        base_rq(&rq, "/api/frrs/relate", "");
        rq.is_post = 1;
        snprintf(rq.origin, sizeof(rq.origin), "http://127.0.0.1:8770");
        rq.origin_count = 1;
        snprintf(rq.ctype, sizeof(rq.ctype), "application/json");
        rq.ctype_count = 1;
        snprintf(rq.fetch_site, sizeof(rq.fetch_site), "cross-site");
        rq.body = l;
        rq.body_len = strlen(l);
        WT_EQ(web_route(&rq, &E.h, 1, g_out, sizeof(g_out), &r), 0);
        WT_EQ(r.status, 403);
    }
    WT_EQ(get("/api/frrs/summary", ""), 200);
    WT_EQ(json_int(body_of(g_out), "rows"), 0);
#ifdef WITH_SQLITE
    WT_EQ(store_int("SELECT COUNT(*) FROM relation"), 0);
    WT_EQ(store_int("SELECT COUNT(*) FROM anom_subject"), 0);
#endif
    WT_EQ(post_h("/api/frrs/relate", l, "http://127.0.0.1:8770", "application/json; charset=utf-8"), 200);
    WT_EQ(post_h("/api/frrs/triage", b, "http://127.0.0.1:8770", "application/json"), 200);
    env_close();
}

/* test_body_rules's: Content-Type, unknown members, bounds, control
 * bytes, ill-formed UTF-8, and an id that names nothing, on both
 * routes. Nothing refused leaves a row. Seen red: the ends' checks in
 * frrs_relate_post() skipped (`ga == 0` and `gb == 0` made `0`: the
 * link to an unknown device written, 200), and frrs_anom_resolve()
 * answering 1 for an id neither the engine nor the store holds (the
 * note on an anomaly that does not exist written, 200). */
static void test_anomaly_body_rules(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char tid[WEB_ANOM_TID_MAX + 1], b[1024], note[300];
    ep(1, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 600, T - 60, tid);
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\"}", tid);
    WT_EQ(post_h("/api/frrs/triage", b, "http://127.0.0.1:8770", "text/plain"), 415);
    WT_HAS(g_out, "bad_content_type");
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"from\":\"%s\",\"to\":\"" MAC1 "\"}", tid);
    WT_EQ(post_h("/api/frrs/relate", b, "http://127.0.0.1:8770", "text/plain"), 415);
    WT_EQ(post_h("/api/frrs/relate", b, "http://127.0.0.1:8770", "application/jsonx"), 415);
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"from\":\"%s\",\"to\":\"" MAC1 "\",\"admin\":true}", tid);
    WT_EQ(post("/api/frrs/relate", b), 400);
    WT_HAS(g_out, "unknown_member");
    WT_EQ(post("/api/frrs/relate", "[1,2]"), 400);
    WT_EQ(post("/api/frrs/relate", "{\"op\":"), 400);
    WT_HAS(g_out, "bad_body");
    /* Ill-formed UTF-8 (a lone 0xff, an overlong slash) in a note: the
     * decoder refuses the body whole. */
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\",\"note\":\"a\xff" "b\"}", tid);
    WT_EQ(post("/api/frrs/triage", b), 400);
    WT_HAS(g_out, "bad_body");
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"from\":\"%s\",\"to\":\"" MAC1 "\",\"note\":\"a\xc0\xaf" "b\"}", tid);
    WT_EQ(post("/api/frrs/relate", b), 400);
    WT_HAS(g_out, "bad_body");
    memset(note, 'n', 241);
    note[241] = '\0';
    WT_EQ(triage(tid, "noise", note), 400);
    WT_HAS(g_out, "too_long");
    WT_EQ(link_add(tid, MAC1, note), 400);
    char want[128];
    snprintf(want, sizeof(want), "{\"error\":\"too_long\",\"member\":\"note\",\"length\":241,\"limit\":%d}",
             WEB_FRRS_NOTE_MAX);
    WT_HAS(body_of(g_out), want);
    WT_LACKS(body_of(g_out), "nnnn");
    /* A control byte, and a bidirectional override (U+202E). */
    WT_EQ(link_add(tid, MAC1, "a\\u0007b"), 400);
    WT_HAS(g_out, "bad_text");
    WT_EQ(link_add(tid, MAC1, "a\xe2\x80\xae" "b"), 400);
    WT_HAS(g_out, "bad_text");
    snprintf(b, sizeof(b), "{\"op\":\"join\",\"from\":\"%s\",\"to\":\"" MAC1 "\"}", tid);
    WT_EQ(post("/api/frrs/relate", b), 400);
    WT_HAS(g_out, "bad_op");
    WT_EQ(post("/api/frrs/relate", "{\"op\":\"add\",\"to\":\"" MAC1 "\"}"), 400);
    WT_HAS(g_out, "missing_from");
    /* Ids that name nothing. */
    WT_EQ(triage("a0123456789abcdef", "noise", NULL), 404);
    WT_HAS(g_out, "no_such_anomaly");
    WT_EQ(triage("a0123", "noise", NULL), 404);
    WT_EQ(triage("aABCDEF0123456789", "noise", NULL), 404);
    WT_EQ(history("a0123456789abcdef"), 404);
    WT_EQ(link_add(tid, "a0123456789abcdef", ""), 404);
    WT_HAS(g_out, "no_such_anomaly");
    WT_EQ(link_add("a0123456789abcdef", MAC1, ""), 404);
    WT_EQ(link_add(tid, "d999999", ""), 404);
    WT_HAS(g_out, "no_such_alert");
    WT_EQ(link_add(tid, MAC2, ""), 404);
    WT_HAS(g_out, "no_such_device");
    WT_EQ(link_add(tid, "not an id", ""), 400);
    WT_HAS(g_out, "bad_id");
    WT_EQ(link_add(tid, "", ""), 400);
    WT_HAS(g_out, "missing_to");
    WT_EQ(get("/api/frrs/summary", ""), 200);
    WT_EQ(json_int(body_of(g_out), "rows"), 0);
#ifdef WITH_SQLITE
    WT_EQ(store_int("SELECT COUNT(*) FROM relation"), 0);
    WT_EQ(store_int("SELECT COUNT(*) FROM anom_subject"), 0);
#endif
    note[240] = '\0';
    WT_EQ(triage(tid, "noise", note), 200);
    WT_EQ(link_add(tid, MAC1, note), 200);
    env_close();
}

/* test_note_over_limit_refused_with_its_limit's: a note over the bound
 * is refused with the bound and what was sent, in bytes, never the
 * text, and the anomaly's history is exactly what it was. */
static void test_anomaly_note_over_limit(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char tid[WEB_ANOM_TID_MAX + 1], note[WEB_FRRS_NOTE_MAX * 2 + 8], want[128];
    static char before[16384];
    ep(1, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 600, T - 60, tid);
    WT_EQ(triage(tid, "noise", "first"), 200);
    WT_EQ(history(tid), 200);
    snprintf(before, sizeof(before), "%s", body_of(g_out));
    WT_EQ(count_of(before, "\"prev_state\":"), 2);
    size_t o = 0;
    for (int i = 0; i < 121; i++) { note[o++] = (char)0xc3; note[o++] = (char)0xa9; }
    note[o] = '\0';
    WT_EQ(triage(tid, "false", note), 400);
    snprintf(want, sizeof(want), "\"length\":242,\"limit\":%d}", WEB_FRRS_NOTE_MAX);
    WT_HAS(body_of(g_out), want);
    WT_EQ(history(tid), 200);
    WT_EQ(strcmp(body_of(g_out), before), 0);
    env_close();
}

/* test_get_cannot_write's: the link's write path answers POST only,
 * its read path GET only. */
static void test_anomaly_get_cannot_write(void) {
    env_open(1);
    char tid[WEB_ANOM_TID_MAX + 1], q[128];
    ep(1, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 600, T - 60, tid);
    snprintf(q, sizeof(q), "id=%s&state=noise", tid);
    WT_EQ(get("/api/frrs/triage", q), 405);
    WT_HAS(g_out, "Allow: POST\r\n");
    snprintf(q, sizeof(q), "op=add&from=%s&to=" MAC1, tid);
    WT_EQ(get("/api/frrs/relate", q), 405);
    WT_HAS(g_out, "Allow: POST\r\n");
    WT_EQ(post("/api/frrs/related", "{}"), 405);
    WT_HAS(g_out, "Allow: GET, HEAD\r\n");
    WT_EQ(related(tid), 200);
    WT_HAS(g_out, "\"links\":[]");
    env_close();
}

/* --web-read-only's (test_read_only_over_socket's router half): no
 * write of either kind, the reads stay and say why. */
static void test_anomaly_read_only(void) {
    env_open(0);
    char tid[WEB_ANOM_TID_MAX + 1];
    ep(1, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 600, T - 60, tid);
    WT_EQ(triage(tid, "noise", NULL), E.have_store ? 405 : 503);
    WT_EQ(link_add(tid, MAC1, ""), E.have_store ? 405 : 503);
    if (E.have_store) WT_HAS(g_out, "read_only");
    WT_EQ(related(tid), 200);
    WT_HAS(g_out, "\"writes\":false");
    WT_EQ(states(tid), 200);
    WT_HAS(g_out, "\"writes\":false");
    env_close();
}

#ifdef WITH_SQLITE
/* One ble_device line into the ledger, as the feed hands it. */
static void ble_heard(const char *addr, int type, const char *iface) {
    char line[320];
    int n = snprintf(line, sizeof(line), "{\"type\":\"ble_device\",\"ts\":%lld,\"addr\":\"%s\","
                     "\"addr_type\":%d,\"iface\":\"%s\",\"name\":\"BLENAME-MARK\",\"has_rssi\":1,"
                     "\"rssi\":-60,\"rssi_best\":-60,\"last_seen\":%lld}", T, addr, type, iface, T);
    web_jrec_t *r = malloc(sizeof(*r));
    WT_ASSERT(r && web_jl_parse(line, (size_t)n, r) == WEB_JL_OK);
    if (r) web_frrs_record(&E.f, r);
    free(r);
}

/* An alert linked to a device with no anomaly in it (owner ruling
 * 2026-11-11): made from either end, listed from both, removed from
 * either. */
static void test_alert_device_links(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char id[40], id2[40], lbl[100], want[200], rm[160];
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    WT_ASSERT(id_of("KARMA_AP", id2, sizeof(id2)));
    alert_label(id, "PORT_SCAN", lbl, sizeof(lbl));
    WT_EQ(link_add(id, MAC1, "seen from the nas"), 200);
    WT_HAS(g_out, "\"unchanged\":false,\"link\":1");
    WT_HAS(links_part(), "{\"link\":1,\"dir\":\"to\",\"kind\":\"device\",\"id\":\"" MAC1 "\",\"label\":\"\",\"held\":true");
    WT_HAS(links_part(), "seen from the nas");
    /* From the device's end. */
    WT_EQ(related(MAC1), 200);
    snprintf(want, sizeof(want), "{\"link\":1,\"dir\":\"from\",\"kind\":\"alert\"");
    WT_HAS(links_part(), want);
    snprintf(want, sizeof(want), "\"label\":\"%s\",\"held\":true", lbl);
    WT_HAS(links_part(), want);
    /* The other order is the same link; a device to another alert is a
     * second one. */
    WT_EQ(link_add(MAC1, id, ""), 200);
    WT_HAS(g_out, "\"unchanged\":true,\"link\":1");
    WT_EQ(link_add(MAC1, id2, ""), 200);
    WT_HAS(g_out, "\"unchanged\":false,\"link\":2");
    WT_EQ(count_of(links_part(), "{\"link\":"), 2);
    WT_EQ(store_int("SELECT COUNT(*) FROM relation WHERE a_kind + b_kind = 2 AND a_kind <> 1"), 2);
    WT_EQ(store_int("SELECT COUNT(*) FROM anom_subject"), 0);
    /* Removed from the device's end: gone from the alert's. */
    snprintf(rm, sizeof(rm), "{\"op\":\"remove\",\"from\":\"" MAC1 "\",\"link\":1}");
    WT_EQ(post("/api/frrs/relate", rm), 200);
    WT_EQ(count_of(links_part(), "{\"link\":"), 1);
    WT_EQ(related(id), 200);
    WT_HAS(g_out, "\"links\":[]");
    /* And from the alert's end. */
    snprintf(rm, sizeof(rm), "{\"op\":\"remove\",\"from\":\"%s\",\"link\":2}", id2);
    WT_EQ(post("/api/frrs/relate", rm), 200);
    WT_EQ(store_int("SELECT COUNT(*) FROM relation"), 0);
    env_close();
}

/* A BLE advertiser as a link's end: named by its address and type (as
 * the TACDB names one), held while the ledger has a row of it, linked
 * to an anomaly or an alert and never to a device or another
 * advertiser; the answer carries the sensor its drawer opens by, and
 * no name of it reaches the store. Unknown, of another type, or
 * anonymous: refused. Once the ledger has let it go (here a new
 * module: a restart, the address rotated away) the link says "held":
 * false and still comes away. Seen red with ble_held() answering 1
 * (the link to an advertiser never heard written, 200; the gone one
 * listed as held). */
static void test_ble_links(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char a[WEB_ANOM_TID_MAX + 1], id[40], rm[160];
    ep(1, "A7", WM_HOST_CONNS, "203.0.113.50", WEB_EP_OPEN, T - 600, T - 60, a);
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    ble_heard(BLE1, 1, "bluetooth-monitor");
    WT_EQ(link_add(a, BLE1 "/1", "the tag by the door"), 200);
    WT_HAS(links_part(), "{\"link\":1,\"dir\":\"to\",\"kind\":\"ble\",\"id\":\"" BLE1 "/1\",\"label\":\"\",\"held\":true");
    WT_HAS(links_part(), "\"iface\":\"bluetooth-monitor\"");
    /* Upper case and the same address again: the one link. */
    WT_EQ(link_add(a, "02:DE:00:00:00:B1/1", ""), 200);
    WT_HAS(g_out, "\"unchanged\":true,\"link\":1");
    WT_EQ(link_add(id, BLE1 "/1", ""), 200);          /* an alert to it */
    /* From the advertiser's end: both. */
    WT_EQ(related(BLE1 "/1"), 200);
    WT_HAS(g_out, "\"kind\":\"ble\",\"label\":\"\",\"held\":true");
    WT_EQ(count_of(links_part(), "{\"link\":"), 2);
    WT_HAS(links_part(), "\"dir\":\"from\",\"kind\":\"anomaly\"");
    WT_HAS(links_part(), "\"dir\":\"from\",\"kind\":\"alert\"");
    WT_HAS(g_out, "\"suggest\":[]");
    /* What is not one, or not held. */
    WT_EQ(link_add(a, BLE1 "/0", ""), 404);           /* another address type */
    WT_HAS(g_out, "no_such_ble");
    WT_EQ(link_add(a, "02:de:00:00:00:b9/1", ""), 404);
    WT_EQ(link_add(a, "00:00:00:00:00:00/255", ""), 400);   /* anonymous */
    WT_HAS(g_out, "bad_id");
    WT_EQ(link_add(a, BLE1 "/7", ""), 400);
    WT_EQ(link_add(a, BLE1 "/", ""), 400);
    WT_EQ(link_add(MAC1, BLE1 "/1", ""), 400);        /* a device to it */
    WT_HAS(g_out, "bad_pair");
    ble_heard("02:de:00:00:00:b2", 1, "ubertooth");
    WT_EQ(link_add(BLE1 "/1", "02:de:00:00:00:b2/1", ""), 400);
    WT_HAS(g_out, "bad_pair");
    WT_EQ(store_int("SELECT COUNT(*) FROM relation"), 2);
    WT_EQ(store_int("SELECT COUNT(*) FROM relation WHERE b_kind = 3 AND b_id = '" BLE1 "/1'"), 2);
    /* The ledger has let it go. */
    store_down();
    WT_ASSERT(!store_has("BLENAME-MARK"));
    store_up(1);
    WT_EQ(related(a), 200);
    WT_HAS(links_part(), "\"kind\":\"ble\",\"id\":\"" BLE1 "/1\",\"label\":\"\",\"held\":false,\"note\":\"the tag by the door\"");
    WT_LACKS(links_part(), "\"iface\"");
    WT_EQ(related(BLE1 "/1"), 200);
    WT_HAS(g_out, "\"kind\":\"ble\",\"label\":\"\",\"held\":false");
    WT_EQ(count_of(links_part(), "{\"link\":"), 2);
    WT_EQ(link_add(a, BLE1 "/1", ""), 404);           /* nothing new to what is gone */
    WT_HAS(g_out, "no_such_ble");
    snprintf(rm, sizeof(rm), "{\"op\":\"remove\",\"from\":\"" BLE1 "/1\",\"link\":1}");
    WT_EQ(post("/api/frrs/relate", rm), 200);
    WT_EQ(store_int("SELECT COUNT(*) FROM relation"), 1);
    env_close();
}

/* An address whose first hex digit is d (one OUI in sixteen, a
 * Raspberry Pi's dc:a6:32 among them) is a device or an advertiser,
 * not a malformed alert id: an alert's id also begins with d, and
 * resolve_ref() refused everything after that letter that was not
 * alphanumeric before it looked at the other shapes. Seen red with
 * that order: 400 bad_id for each of these. */
static void test_ids_beginning_d(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char a[WEB_ANOM_TID_MAX + 1], t[WEB_ANOM_TID_MAX + 1];
    ep(1, "A7", WM_HOST_CONNS, "203.0.113.50", WEB_EP_OPEN, T - 600, T - 60, a);
    /* Held: an anomaly is keyed by it. */
    ep(2, "A2", WM_DEV_PRESENT, "dc:a6:32:00:00:01", WEB_EP_OPEN, T - 600, T - 60, t);
    WT_EQ(related("dc:a6:32:00:00:01"), 200);
    WT_HAS(g_out, "\"kind\":\"device\"");
    WT_EQ(link_add(a, "dc:a6:32:00:00:01", ""), 200);
    WT_HAS(links_part(), "\"kind\":\"device\",\"id\":\"dc:a6:32:00:00:01\"");
    ble_heard("de:ad:00:00:00:b1", 1, "bluetooth-monitor");
    WT_EQ(link_add(a, "de:ad:00:00:00:b1/1", ""), 200);
    WT_EQ(related("de:ad:00:00:00:b1/1"), 200);
    WT_HAS(g_out, "\"kind\":\"ble\"");
    /* Still not ids: an alert's shape with something else in it. */
    WT_EQ(related("d12:34"), 400);
    WT_EQ(related("dc:a6:32:00:00:0"), 400);
    WT_EQ(related("s%3A1"), 400);
    env_close();
}
#endif

#ifdef WITH_SQLITE
/* test_no_credential_and_no_stream_string_stored's: a link to a
 * cleartext credential's alert stores its type and address, none of
 * its key (which names a username); an anomaly's evidence line, the
 * one stream-derived sentence an episode has, reaches no table here.
 * Seen red with the alert's label built from the incident's key in
 * resolve_ref() (the username in the file). */
static void test_nothing_from_the_stream_stored(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char tid[WEB_ANOM_TID_MAX + 1], id[40];
    ep(1, "A8", -1, "192.0.2.16", WEB_EP_OPEN, T - 600, T - 60, tid);
    WT_ASSERT(id_of("CLEARTEXT_CRED", id, sizeof(id)));
    WT_EQ(link_add(tid, id, "the thermostat"), 200);
    WT_LACKS(g_out, "demo-user");
    WT_HAS(g_out, "\"label\":\"CLEARTEXT_CRED 192.0.2.16\"");
    WT_EQ(triage(tid, "incident", "ftp in the clear"), 200);
    WT_EQ(related(id), 200);
    WT_LACKS(g_out, "demo-user");
    WT_LACKS(g_out, "EVMARK");
    store_down();
    WT_ASSERT(!store_has("demo-user"));
    WT_ASSERT(!store_has("00c0ffee"));
    WT_ASSERT(!store_has("EVMARK"));
    WT_ASSERT(store_has("CLEARTEXT_CRED 192.0.2.16"));   /* the scan reads the file */
    WT_ASSERT(store_has("the thermostat"));
    env_close();
}

/* test_unchanged_write_adds_no_row's: the state an anomaly already has,
 * with no new note, is no row. A state carried from an earlier episode
 * is not this episode's: saying it again is a row, and it is then no
 * longer carried. Seen red with the `cur.carried` line taken out of
 * post_triage() (the second episode's "noise" unchanged, one row, still
 * carried). */
static void test_anomaly_unchanged_write_adds_no_row(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char tid[WEB_ANOM_TID_MAX + 1];
    ep(1, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 600, T - 60, tid);
    WT_EQ(triage(tid, "noise", NULL), 200);
    WT_HAS(g_out, "\"unchanged\":false");
    WT_EQ(triage(tid, "noise", NULL), 200);
    WT_HAS(g_out, "\"unchanged\":true");
    WT_EQ(store_int("SELECT COUNT(*) FROM triage"), 1);
    WT_EQ(triage(tid, "untriaged", NULL), 200);
    WT_EQ(triage(tid, "untriaged", NULL), 200);
    WT_HAS(g_out, "\"unchanged\":true");
    WT_EQ(store_int("SELECT COUNT(*) FROM triage"), 2);
    WT_EQ(triage(tid, "noise", NULL), 200);
    /* The episode closes and the rule fires again: a later episode. */
    an_reset();
    ep(2, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 100, T - 10, NULL);
    WT_EQ(states(tid), 200);
    WT_HAS(g_out, "\"state\":\"noise\"");
    WT_HAS(g_out, "\"carried\":true");
    WT_EQ(triage(tid, "noise", NULL), 200);
    WT_HAS(g_out, "\"unchanged\":false");
    WT_HAS(g_out, "\"carried\":false");
    WT_EQ(store_int("SELECT COUNT(*) FROM triage"), 4);
    WT_EQ(store_int("SELECT COUNT(*) FROM triage WHERE first_seen = " "1792627100"), 1);
    env_close();
}

/* test_history_folds_never_refuses's: one anomaly's history past
 * WEB_FRRS_HIST_PER folds, its first row and its newest kept, and no
 * write is refused for it. */
static void test_anomaly_history_folds(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char tid[WEB_ANOM_TID_MAX + 1];
    ep(1, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 600, T - 60, tid);
    for (int i = 0; i < WEB_FRRS_HIST_PER + 6; i++)
        WT_EQ(triage(tid, i % 2 ? "false" : "noise", NULL), 200);
    WT_EQ(store_int("SELECT COUNT(*) FROM triage"), WEB_FRRS_HIST_PER);
    WT_EQ(history(tid), 200);
    WT_HAS(g_out, "\"current\":{\"state\":\"false\"");
    WT_EQ(json_int(body_of(g_out), "folded"), 6);
    env_close();
}

/* test_triage_cap_folds_and_clears's, for what is new: at the table's
 * cap an anomaly's current row is never folded as another anomaly's
 * superseded one. X and Y are two anomalies whose episodes began in the
 * same second, each with one row; the table is filled with single rows,
 * and a third anomaly's writes then fold only its own superseded rows.
 * Seen red with the id left out of the descriptor in frrs_anom_subj()
 * (addr ""): X's row, then sharing (type -1, "", 0, first_seen) with
 * Y's and Z's, read as superseded and was folded (X untriaged). */
static void test_anomaly_cap_keeps_current_rows(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    E.f.triage_cap = 40;
    char x[WEB_ANOM_TID_MAX + 1], y[WEB_ANOM_TID_MAX + 1], z[WEB_ANOM_TID_MAX + 1];
    ep(1, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 600, T - 60, x);
    ep(2, "A7", WM_HOST_CONNS, "192.0.2.16", WEB_EP_OPEN, T - 600, T - 60, y);
    ep(3, "A8", -1, "192.0.2.21", WEB_EP_OPEN, T - 600, T - 60, z);
    WT_EQ(triage(x, "incident", NULL), 200);
    WT_EQ(triage(y, "known", NULL), 200);
    WT_EQ(sql_on(E.store_path,
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 36)"
        " INSERT INTO triage (subject, type, addr, port, first_seen, state, via, ts)"
        " SELECT 'x1:' || i, 1, '', 0, i, 2, 0, 1792627200 FROM n"), 0);
    WT_EQ(store_int("SELECT COUNT(*) FROM triage"), 38);
    for (int i = 0; i < 8; i++) WT_EQ(triage(z, i % 2 ? "false" : "noise", NULL), 200);
    WT_ASSERT(store_int("SELECT COUNT(*) FROM triage") <= 40);
    WT_EQ(states(x), 200);
    WT_HAS(g_out, "\"state\":\"incident\"");
    WT_EQ(states(y), 200);
    WT_HAS(g_out, "\"state\":\"known\"");
    WT_EQ(states(z), 200);
    WT_HAS(g_out, "\"state\":\"false\"");
    WT_EQ(store_int("SELECT COUNT(*) FROM triage WHERE subject LIKE 'x1:%'"), 36);
    env_close();
}

/* Persistence, and what an anomaly's id names (test_finding_set_once's
 * place: how a note stays on the finding it was written on). The store
 * closed and opened again holds the decision; an episode of the same
 * rule, metric and key detected again (another engine id, the same
 * first_seen) shows it, not carried; a later episode of it shows it
 * carried, with the episode it was made on; with no episode held the
 * id still resolves from the store ("held": false) and keeps its
 * history. Another key, another rule and another metric are other
 * findings and untriaged: seen red with the key left out of the hash in
 * web_anomaly_tid() (MAC2's episode took MAC1's "known"). */
static void test_anomaly_survives_reopen_and_redetection(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char tid[WEB_ANOM_TID_MAX + 1], other[WEB_ANOM_TID_MAX + 1], want[96];
    ep(1, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 600, T - 60, tid);
    WT_EQ(triage(tid, "known", "ours: the night printer"), 200);
    store_down();
    store_up(1);
    an_reset();
    char again[WEB_ANOM_TID_MAX + 1];
    ep(41, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_CLOSED, T - 600, T - 30, again);
    WT_EQ(strcmp(tid, again), 0);
    WT_EQ(states(tid), 200);
    WT_HAS(g_out, "\"state\":\"known\"");
    WT_HAS(g_out, "ours: the night printer");
    WT_HAS(g_out, "\"carried\":false");
    /* Other findings: another key, another rule, another metric. */
    ep(42, "A3", WM_DEV_PRESENT, MAC2, WEB_EP_OPEN, T - 600, T - 60, other);
    WT_ASSERT(strcmp(other, tid) != 0);
    WT_EQ(states(other), 200);
    snprintf(want, sizeof(want), "\"untriaged\":[\"%s\"]", other);
    WT_HAS(g_out, want);
    ep(43, "A4", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 600, T - 60, other);
    WT_EQ(states(other), 200);
    WT_HAS(g_out, "\"triage\":{}");
    ep(44, "A3", WM_DEV_FRAMES, MAC1, WEB_EP_OPEN, T - 600, T - 60, other);
    WT_EQ(states(other), 200);
    WT_HAS(g_out, "\"triage\":{}");
    /* A later episode of the same finding. */
    an_reset();
    ep(7, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 100, T - 10, NULL);
    WT_EQ(history(tid), 200);
    snprintf(want, sizeof(want), "\"episode\":%lld,\"carried\":true", T - 600);
    WT_HAS(g_out, want);
    WT_HAS(g_out, "\"current\":{\"state\":\"known\"");
    /* The engine has let it go. */
    an_reset();
    WT_EQ(history(tid), 200);
    WT_HAS(g_out, "\"key\":\"" MAC1 "\",\"held\":false,\"open\":false,\"first_seen\":null");
    WT_HAS(g_out, "\"current\":{\"state\":\"known\"");
    WT_HAS(g_out, "ours: the night printer");
    WT_HAS(g_out, "\"carried\":false");
    /* One never triaged and not held is nothing. */
    WT_EQ(states(other), 200);
    snprintf(want, sizeof(want), "\"missing\":[\"%s\"]", other);
    WT_HAS(g_out, want);
    env_close();
}

/* The id is a hash: when the store's descriptor of it is not the
 * engine's, the id is refused on every route and nothing is joined.
 * Seen red with the comparison taken out of frrs_anom_resolve() (the
 * other anomaly's note and state answered for this one, 200). */
static void test_anomaly_id_collision_refused(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char tid[WEB_ANOM_TID_MAX + 1], want[96];
    ep(1, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 600, T - 60, tid);
    WT_EQ(triage(tid, "known", "the other one's note"), 200);
    /* As if another anomaly had been filed under this id first. */
    WT_EQ(sql_on(E.store_path, "UPDATE anom_subject SET key = '" MAC2 "'"), 0);
    WT_EQ(history(tid), 409);
    WT_HAS(g_out, "id_collision");
    WT_LACKS(g_out, "the other one's note");
    WT_EQ(triage(tid, "noise", NULL), 409);
    WT_EQ(related(tid), 409);
    WT_EQ(link_add(tid, MAC1, ""), 409);
    WT_EQ(states(tid), 200);
    snprintf(want, sizeof(want), "\"missing\":[\"%s\"]", tid);
    WT_HAS(g_out, want);
    WT_LACKS(g_out, "the other one's note");
    WT_EQ(store_int("SELECT COUNT(*) FROM triage"), 1);
    env_close();
}

/* One table, two kinds of subject, never mixed: an alert's rows and an
 * anomaly's answer only for their own, and the TACDB export (filed by
 * an alert's descriptor, for another sensor) carries the alert's
 * decision and none of the anomaly's. Seen red with `WHERE type >= 0`
 * taken out of frrs_triage_export() (the anomaly's id and note in the
 * file, a second triage line). */
static void test_alert_and_anomaly_rows_apart(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char tid[WEB_ANOM_TID_MAX + 1], id[40];
    ep(1, "A7", WM_HOST_CONNS, "203.0.113.50", WEB_EP_OPEN, T - 600, T - 60, tid);
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    WT_EQ(triage(id, "noise", "alert-note"), 200);
    WT_EQ(triage(tid, "incident", "anomaly-note"), 200);
    WT_EQ(states(id), 200);
    WT_HAS(g_out, "\"state\":\"noise\"");
    WT_LACKS(g_out, "anomaly-note");
    WT_EQ(states(tid), 200);
    WT_HAS(g_out, "\"state\":\"incident\"");
    WT_LACKS(g_out, "alert-note");
    WT_EQ(history(id), 200);
    WT_EQ(json_int(body_of(g_out), "history_n"), 1);
    WT_EQ(history(tid), 200);
    WT_EQ(json_int(body_of(g_out), "history_n"), 1);
    WT_EQ(get("/api/frrs/export", ""), 200);
    WT_EQ(count_of(g_out, "{\"type\":\"triage\""), 1);
    WT_HAS(g_out, "alert-note");
    WT_LACKS(g_out, "anomaly-note");
    WT_LACKS(g_out, tid);
    /* The alert routes' own join sees only the alert's. */
    WT_EQ(get("/api/alerts", "triage=incident&limit=100"), 200);
    WT_HAS(g_out, "\"incident\":0");
    env_close();
}
#endif /* WITH_SQLITE: stored, folds, identity */

#ifdef WITH_SQLITE
static int g_verdicts, g_verdict_anom, g_verdict_state;
static int verdict_seen(void *ctx, const web_frrs_verdict_t *v) {
    (void)ctx;
    g_verdicts++;
    if (v->type < 0) g_verdict_anom++;
    g_verdict_state = v->state;
    return 0;
}

/* The fleet export's verdicts (web_fleet.h, #192) are alerts' only: an
 * anomaly's decision, newer than the alert's, is neither handed to the
 * exporter nor counted against its limit (with room for one row the
 * alert's is the one read), and /api/fleet/export carries one verdict
 * line. Seen red with `t.type >= 0 AND` taken out of
 * web_frrs_verdicts() (the anomaly's row handed over, and with a limit
 * of one the alert's verdict not read at all). */
static void test_fleet_verdicts_are_alerts_only(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char tid[WEB_ANOM_TID_MAX + 1], id[40];
    ep(1, "A7", WM_HOST_CONNS, "203.0.113.50", WEB_EP_OPEN, T - 600, T - 60, tid);
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    WT_EQ(triage(id, "noise", NULL), 200);
    WT_EQ(triage(tid, "incident", NULL), 200);        /* the newer row */
    g_verdicts = g_verdict_anom = 0;
    WT_EQ(web_frrs_verdicts(&E.f, 0, -1, 0, 100, verdict_seen, NULL), 1);
    WT_EQ(g_verdicts, 1);
    WT_EQ(g_verdict_anom, 0);
    g_verdicts = g_verdict_anom = 0;
    g_verdict_state = -1;
    WT_EQ(web_frrs_verdicts(&E.f, 0, -1, 0, 1, verdict_seen, NULL), 1);
    WT_EQ(g_verdict_anom, 0);
    WT_EQ(g_verdict_state, WEB_TRI_NOISE);
    env_close();
}

/* ── links ──────────────────────────────────────────────────────────── */

/* A link is read from both ends and removed from either: an anomaly to
 * an alert, to a device and to another anomaly. The other end's triage
 * comes with it. The same pair again, in either direction, is the link
 * that is there. */
static void test_links_both_directions(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char a[WEB_ANOM_TID_MAX + 1], b[WEB_ANOM_TID_MAX + 1], id[40], subj[40], want[200], lbl[100];
    ep(1, "A7", WM_HOST_CONNS, "203.0.113.50", WEB_EP_OPEN, T - 600, T - 60, a);
    ep(2, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_CLOSED, T - 900, T - 700, b);
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    alert_label(id, "PORT_SCAN", lbl, sizeof(lbl));
    WT_EQ(link_add(a, id, "the <i>scanner</i> again"), 200);
    WT_HAS(g_out, "\"ok\":true,\"unchanged\":false,\"link\":1");
    json_str(links_part(), "id", subj, sizeof(subj));
    WT_ASSERT(subj[0] == 'd');
    WT_HAS(links_part(), "\"dir\":\"to\",\"kind\":\"alert\"");
    snprintf(want, sizeof(want), "\"label\":\"%s\",\"held\":true", lbl);
    WT_HAS(links_part(), want);
    WT_HAS(links_part(), "the \\u003ci\\u003escanner\\u003c/i\\u003e again");
    WT_LACKS(links_part(), "<i>");
    WT_HAS(links_part(), "\"peer\":\"127.0.0.1\"");
    WT_HAS(links_part(), "\"triage\":null");
    /* From the alert's end, by the id its page has. */
    WT_EQ(triage(a, "incident", "fan-out with the scan"), 200);
    WT_EQ(related(id), 200);
    snprintf(want, sizeof(want), "\"kind\":\"alert\",\"label\":\"%s\",\"held\":true", lbl);
    WT_HAS(g_out, want);
    snprintf(want, sizeof(want), "{\"link\":1,\"dir\":\"from\",\"kind\":\"anomaly\",\"id\":\"%s\","
             "\"label\":\"A7 fanout 203.0.113.50\",\"held\":true", a);
    WT_HAS(links_part(), want);
    WT_HAS(links_part(), "\"triage\":{\"state\":\"incident\"");
    WT_HAS(links_part(), "fan-out with the scan");
    /* To a device, and to another anomaly. */
    WT_EQ(link_add(a, MAC1, ""), 200);
    WT_EQ(link_add(a, b, ""), 200);
    WT_EQ(count_of(links_part(), "{\"link\":"), 3);
    WT_EQ(related(MAC1), 200);
    WT_HAS(g_out, "\"kind\":\"device\"");
    snprintf(want, sizeof(want), "\"dir\":\"from\",\"kind\":\"anomaly\",\"id\":\"%s\"", a);
    WT_HAS(links_part(), want);
    /* The device's own anomalies, each with its triage. */
    snprintf(want, sizeof(want), "\"anomalies\":[{\"id\":\"%s\",\"label\":\"A3 hours " MAC1 "\"", b);
    WT_HAS(g_out, want);
    WT_EQ(related(b), 200);
    WT_HAS(links_part(), "\"dir\":\"from\",\"kind\":\"anomaly\"");
    /* Again, and the other way round: the link that is there. */
    WT_EQ(link_add(a, id, "x"), 200);
    WT_HAS(g_out, "\"unchanged\":true,\"link\":1");
    WT_EQ(link_add(id, a, "x"), 200);
    WT_HAS(g_out, "\"unchanged\":true,\"link\":1");
    WT_EQ(link_add(b, a, ""), 200);
    WT_HAS(g_out, "\"unchanged\":true,\"link\":3");
#ifdef WITH_SQLITE
    WT_EQ(store_int("SELECT COUNT(*) FROM relation"), 3);
    WT_ASSERT(store_has("the <i>scanner</i> again"));
#endif
    /* Removed from the alert's end: gone from both. */
    char rm[160];
    snprintf(rm, sizeof(rm), "{\"op\":\"remove\",\"from\":\"%s\",\"link\":1}", id);
    WT_EQ(post("/api/frrs/relate", rm), 200);
    WT_HAS(g_out, "\"links\":[]");
    WT_EQ(related(a), 200);
    WT_EQ(count_of(links_part(), "{\"link\":"), 2);
    WT_LACKS(links_part(), "PORT_SCAN");
    WT_EQ(get("/api/health", ""), 200);
    WT_HAS(g_out, "\"anomaly_subjects\":2,\"links\":2");
    env_close();
}

/* What a link may be: an anomaly to anything, an alert to a device or
 * a BLE advertiser; never alert to alert, device to device, or a thing
 * to itself; each finding at most WEB_REL_PER of them (a write past it
 * refused, never an older link dropped); removed only by a finding that
 * is one of its ends. Seen red: pair_ok() answering 1 past its self
 * check (the alert-to-alert and device-to-device links written); the
 * per-end bound taken out of
 * link_add() (the 33rd written); the END_IS() clause taken out of
 * link_remove() (another finding's link removed, 200). */
static void test_link_guards(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    char a[WEB_ANOM_TID_MAX + 1], t[WEB_ANOM_TID_MAX + 1], id[40], id2[40], key[24], rm[160];
    ep(1, "A7", WM_HOST_CONNS, "203.0.113.50", WEB_EP_OPEN, T - 600, T - 60, a);
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    WT_ASSERT(id_of("KARMA_AP", id2, sizeof(id2)));
    WT_EQ(link_add(id, id2, ""), 400);                /* alert to alert */
    WT_HAS(g_out, "bad_pair");
    WT_EQ(link_add(MAC1, MAC3, ""), 400);             /* device to device */
    WT_HAS(g_out, "bad_pair");
    WT_EQ(link_add(id, id, ""), 400);
    WT_EQ(link_add(MAC1, MAC1, ""), 400);
    WT_EQ(link_add(a, a, ""), 400);
    WT_HAS(g_out, "bad_pair");
#ifdef WITH_SQLITE
    WT_EQ(store_int("SELECT COUNT(*) FROM relation"), 0);
#endif
    for (int i = 0; i < WEB_REL_PER + 1; i++) {
        snprintf(key, sizeof(key), "02:aa:00:00:00:%02x", i + 1);
        ep(10 + i, "A2", WM_DEV_PRESENT, key, WEB_EP_OPEN, T - 600, T - 60, t);
        WT_EQ(link_add(a, t, ""), i < WEB_REL_PER ? 200 : 507);
    }
    WT_HAS(g_out, "links_full");
    WT_EQ(related(a), 200);
    WT_EQ(count_of(links_part(), "{\"link\":"), WEB_REL_PER);
    WT_HAS(g_out, "\"links_more\":false");
    /* t is not an end of link 1 (a to the first of them). */
    snprintf(rm, sizeof(rm), "{\"op\":\"remove\",\"from\":\"%s\",\"link\":1}", t);
    WT_EQ(post("/api/frrs/relate", rm), 404);
    WT_HAS(g_out, "no_such_link");
    snprintf(rm, sizeof(rm), "{\"op\":\"remove\",\"from\":\"%s\",\"link\":0}", a);
    WT_EQ(post("/api/frrs/relate", rm), 400);
    WT_HAS(g_out, "bad_link");
    snprintf(rm, sizeof(rm), "{\"op\":\"remove\",\"from\":\"%s\",\"link\":\"1\"}", a);
    WT_EQ(post("/api/frrs/relate", rm), 400);
    snprintf(rm, sizeof(rm), "{\"op\":\"remove\",\"from\":\"%s\",\"link\":9999}", a);
    WT_EQ(post("/api/frrs/relate", rm), 404);
#ifdef WITH_SQLITE
    WT_EQ(store_int("SELECT COUNT(*) FROM relation"), WEB_REL_PER);
#endif
    snprintf(rm, sizeof(rm), "{\"op\":\"remove\",\"from\":\"%s\",\"link\":1}", a);
    WT_EQ(post("/api/frrs/relate", rm), 200);
    WT_EQ(link_add(a, t, ""), 200);                   /* room again */
    env_close();
}

/* A link whose end is gone: the alert out of sloth.db, the anomaly out
 * of the engine. The view is whole, each such end "held": false with
 * the label the link kept, and the link can still be removed. Seen red
 * with `held` answered true for every link in related_json() (the page
 * would then offer to open an alert that is not there). */
static void test_dangling_target(void) {
    env_open(1);
    if (!E.have_store || !E.have_db) { env_close(); return; }
    char a[WEB_ANOM_TID_MAX + 1], b[WEB_ANOM_TID_MAX + 1], id[40], rm[160], want[200], lbl[100], ty[48];
    ep(1, "A7", WM_HOST_CONNS, "203.0.113.50", WEB_EP_OPEN, T - 600, T - 60, a);
    ep(2, "A3", WM_DEV_PRESENT, MAC2, WEB_EP_CLOSED, T - 900, T - 700, b);
    /* An alert only sloth.db holds (a stream incident would still be
     * the stream's after the file lost it). */
    WT_ASSERT(db_only_alert(id, sizeof(id), ty, sizeof(ty)));
    alert_label(id, ty, lbl, sizeof(lbl));
    WT_EQ(link_add(a, id, "kept"), 200);
    WT_EQ(link_add(a, b, ""), 200);
    WT_EQ(count_of(links_part(), "\"held\":true"), 2);
    /* sloth.db compacted, and the engine a day on. */
    WT_EQ(sdb_exec(E.sdb_path, "DELETE FROM alerts"), 0);
    an_reset();
    WT_EQ(related(a), 200);
    WT_HAS(g_out, "\"kind\":\"anomaly\",\"label\":\"A7 fanout 203.0.113.50\",\"held\":false");
    WT_EQ(count_of(links_part(), "{\"link\":"), 2);
    WT_HAS(links_part(), "\"kind\":\"alert\"");
    snprintf(want, sizeof(want), "\"label\":\"%s\",\"held\":false,\"note\":\"kept\"", lbl);
    WT_HAS(links_part(), want);
    snprintf(want, sizeof(want), "\"id\":\"%s\",\"label\":\"A3 hours " MAC2 "\",\"held\":false", b);
    WT_HAS(links_part(), want);
    WT_LACKS(links_part(), "\"held\":true");
    WT_HAS(g_out, "\"suggest\":[]");
    /* From the gone alert's id: its link is still listed. */
    WT_EQ(related(id), 200);
    WT_HAS(g_out, "\"held\":false");
    /* A new link to what is gone is refused; the old ones come away. */
    WT_EQ(link_add(a, id, ""), 404);
    snprintf(rm, sizeof(rm), "{\"op\":\"remove\",\"from\":\"%s\",\"link\":1}", a);
    WT_EQ(post("/api/frrs/relate", rm), 200);
    WT_EQ(count_of(links_part(), "{\"link\":"), 1);
    WT_EQ(store_int("SELECT COUNT(*) FROM relation"), 1);
    env_close();
}

/* ── candidates ─────────────────────────────────────────────────────── */

/* The KARMA alert's span in sloth.db, set so the window's edges are the
 * test's own. */
static void karma_span(long long first, long long last) {
    char sql[256];
    snprintf(sql, sizeof(sql), "UPDATE alerts SET first_seen = %lld, last_seen = %lld"
             " WHERE key LIKE 'karma:%%'", first, last);
    WT_EQ(sdb_exec(E.sdb_path, sql), 0);
}

/* Candidates: the same MAC, spans overlapping or within
 * WEB_REL_WINDOW_S, both edges to the second; another MAC is none;
 * nothing is stored by being offered; one POST accepts one, and it is
 * then a link and no longer offered; an alert offers its anomalies and
 * an anomaly the other anomalies on its key. The wording is the
 * subject and the time, never a cause. Seen red: WEB_REL_WINDOW_S made
 * 601 (the two spans one second outside offered); `same` made always
 * true in cand_alerts() (the other MAC's anomaly offered the stream's
 * incidents). */
static void test_suggestions(void) {
    env_open(1);
    if (!E.have_store || !E.have_db) { env_close(); return; }
    /* The window as the documents state it, not the constant: a
     * changed constant has to fail here. */
    const long long F = T - 7200, L = T - 7000, W = 600;
    WT_EQ(WEB_REL_WINDOW_S, 600);
    char a[WEB_ANOM_TID_MAX + 1], o[WEB_ANOM_TID_MAX + 1], kid[40], want[200];
    karma_span(F, L);
    WT_ASSERT(id_of("KARMA_AP", kid, sizeof(kid)));
    /* Ends exactly the window before the alert begins: offered. */
    ep(1, "A3", WM_DEV_PRESENT, KARMA, WEB_EP_CLOSED, F - W - 100, F - W, a);
    WT_EQ(related(a), 200);
    WT_EQ(count_of(suggest_part(), "{\"kind\":\"alert\""), 1);
    WT_HAS(suggest_part(), "\"label\":\"KARMA_AP " KARMA "\",\"basis\":\"same device, within 10 minutes\"");
    WT_HAS(g_out, "\"window_s\":600");
    WT_HAS(g_out, "a passive sensor corroborates, it does not confirm");
    WT_LACKS(g_out, "caused");
    WT_LACKS(g_out, "because");
    WT_EQ(store_int("SELECT COUNT(*) FROM relation"), 0);     /* offered, not stored */
    WT_EQ(store_int("SELECT COUNT(*) FROM anom_subject"), 0);
    /* One second earlier: not. */
    an_reset();
    ep(1, "A3", WM_DEV_PRESENT, KARMA, WEB_EP_CLOSED, F - W - 100, F - W - 1, a);
    WT_EQ(related(a), 200);
    WT_HAS(g_out, "\"suggest\":[]");
    /* Begins exactly the window after the alert was last seen: offered;
     * a second later: not. */
    an_reset();
    ep(1, "A3", WM_DEV_PRESENT, KARMA, WEB_EP_CLOSED, L + W, L + W + 50, a);
    WT_EQ(related(a), 200);
    WT_EQ(count_of(suggest_part(), "{\"kind\":\"alert\""), 1);
    an_reset();
    ep(1, "A3", WM_DEV_PRESENT, KARMA, WEB_EP_CLOSED, L + W + 1, L + W + 50, a);
    WT_EQ(related(a), 200);
    WT_HAS(g_out, "\"suggest\":[]");
    /* Overlapping: said so. Another MAC at the same time: none. */
    an_reset();
    ep(1, "A3", WM_DEV_PRESENT, KARMA, WEB_EP_OPEN, F + 10, F + 60, a);
    ep(2, "A3", WM_DEV_PRESENT, MAC2, WEB_EP_OPEN, F + 10, F + 60, o);
    WT_EQ(related(o), 200);
    WT_HAS(g_out, "\"suggest\":[]");
    WT_EQ(related(a), 200);
    WT_HAS(suggest_part(), "\"basis\":\"same device, overlapping in time\"");
    char sid[40];
    json_str(suggest_part(), "id", sid, sizeof(sid));
    WT_ASSERT(sid[0] == 'd');
    /* The alert offers the anomaly back, and only that MAC's. */
    WT_EQ(related(kid), 200);
    snprintf(want, sizeof(want), "{\"kind\":\"anomaly\",\"id\":\"%s\",\"label\":\"A3 hours " KARMA "\","
             "\"basis\":\"same device, overlapping in time\"", a);
    WT_HAS(suggest_part(), want);
    WT_LACKS(suggest_part(), o);
    /* Accepted with the one POST that makes any link. */
    WT_EQ(link_add(a, sid, ""), 200);
    WT_HAS(links_part(), "\"label\":\"KARMA_AP " KARMA "\",\"held\":true");
    WT_HAS(g_out, "\"suggest\":[]");
    WT_EQ(store_int("SELECT COUNT(*) FROM relation"), 1);
    WT_EQ(related(kid), 200);
    WT_HAS(g_out, "\"suggest\":[]");
    WT_EQ(count_of(links_part(), "{\"link\":"), 1);
    /* Two anomalies on one key: each offers the other. */
    char v[WEB_ANOM_TID_MAX + 1];
    ep(3, "A4", WM_DEV_PRESENT, KARMA, WEB_EP_OPEN, F + 30, F + 90, v);
    WT_EQ(related(a), 200);
    snprintf(want, sizeof(want), "{\"kind\":\"anomaly\",\"id\":\"%s\",\"label\":\"A4 vendor " KARMA "\"", v);
    WT_HAS(suggest_part(), want);
    /* An address: worded as one. */
    char ip[WEB_ANOM_TID_MAX + 1], cid[40];
    WT_ASSERT(id_of("CLEARTEXT_CRED", cid, sizeof(cid)));
    WT_EQ(sdb_exec(E.sdb_path, "UPDATE alerts SET first_seen = 1792620000, last_seen = 1792620100"
                               " WHERE match_ip = '192.0.2.16'"), 0);
    ep(4, "A8", -1, "192.0.2.16", WEB_EP_OPEN, 1792620050, 1792620090, ip);
    WT_EQ(related(ip), 200);
    WT_HAS(suggest_part(), "\"basis\":\"same address, overlapping in time\"");
    WT_LACKS(suggest_part(), "demo-user");
    env_close();
}

static double ms_since(const struct timespec *a) {
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    return (double)(b.tv_sec - a->tv_sec) * 1e3 + (double)(b.tv_nsec - a->tv_nsec) / 1e6;
}

/* The candidate read on the suite's large alerts table (test_alerts.c's
 * fill: 30,000 rows on keys of about 114, every one naming 10.1.0.9,
 * spread over 30 days): one connection under the request's 250 ms
 * budget, at most WEB_REL_ALERT_SCAN of sloth.db's alerts read for it
 * and at most WEB_REL_SUGGEST offered. The time is printed for the
 * report. */
static void test_suggestions_stay_inside_the_budget(void) {
    env_open(1);
    if (!E.have_store || !E.have_db) { env_close(); return; }
    char p[TEST_TMP_MAX + 32], sql[1024], a[WEB_ANOM_TID_MAX + 1];
    snprintf(p, sizeof(p), "%s/big.db", E.dir);
    WT_EQ(sdb_make(p, db_schema_version(), 0), 0);
    const long long rows = 30000, per = 114;
    snprintf(sql, sizeof(sql),
        "BEGIN; WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i < %lld)"
        " INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,match_ip,count)"
        " SELECT 'big:' || (i / %lld) || ':10.1.' || ((i / %lld) %% 250) || '.9',"
        " %lld - (i * 2592000 / %lld), %lld - (i * 2592000 / %lld) + 60, (i / %lld) %% 90,"
        " i %% 3, 'BIG', '10.1.0.9 scanned 9 distinct ports', '10.1.0.9', 1 FROM n; COMMIT;",
        rows - 1, per, per, T, rows, T, rows, per);
    WT_EQ(sdb_exec(p, sql), 0);
    web_slothdb_t big;
    web_slothdb_init(&big, p, NULL);
    E.m4.sdb = &big;
    ep(1, "A8", -1, "10.1.0.9", WEB_EP_OPEN, T - 900, T - 30, a);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int st = related(a);
    double ms = ms_since(&t0);
    fprintf(stderr, "    /api/frrs/related on %lld alert rows: %.1f ms, %d offered\n", rows, ms,
            count_of(suggest_part(), "{\"kind\":"));
    WT_EQ(st, 200);
    WT_ASSERT(ms < 250.0 * web_sdb_test_budget_scale);
    int n = count_of(suggest_part(), "{\"kind\":\"alert\"");
    WT_ASSERT(n >= 1 && n <= WEB_REL_SUGGEST);
    WT_HAS(suggest_part(), "\"basis\":\"same address, overlapping in time\"");
    WT_EQ(store_int("SELECT COUNT(*) FROM relation"), 0);
    E.m4.sdb = &E.sdb;
    web_slothdb_destroy(&big);
    unlink(p);
    env_close();
}

/* The evidence bundle carries what the alert's page shows: its links,
 * each linked anomaly's triage, and the candidates marked as not
 * stored; a device's carries its links and its own anomalies' triage.
 * The glossary says what they are. */
static void test_bundle_carries_links_and_anomaly_triage(void) {
    env_open(1);
    if (!E.have_store || !E.have_db) { env_close(); return; }
    char a[WEB_ANOM_TID_MAX + 1], id[40], q[96];
    ep(1, "A7", WM_HOST_CONNS, "203.0.113.50", WEB_EP_OPEN, T - 600, T - 60, a);
    ep(2, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 600, T - 60, NULL);
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    WT_EQ(link_add(a, id, "bundle-link-note"), 200);
    WT_EQ(link_add(a, MAC1, ""), 200);
    WT_EQ(triage(a, "incident", "bundle-triage-note"), 200);
    snprintf(q, sizeof(q), "kind=alert&id=%s", id);
    WT_EQ(get("/api/bundle", q), 200);
    WT_HAS(g_out, "\"related\":{\"id\":\"");
    WT_HAS(g_out, "bundle-link-note");
    WT_HAS(g_out, "bundle-triage-note");
    WT_HAS(g_out, "{\"what\":\"alert.related\",\"ms\":");
    WT_HAS(g_out, "\"related\":\"the operator");
    WT_HAS(g_out, "links and the anomaly triage as /api/frrs/related");
    WT_HAS(g_out, "has NOT stored");
    WT_EQ(get("/api/bundle", "kind=device&id=" MAC1), 200);
    WT_HAS(g_out, "{\"what\":\"device.related\",\"ms\":");
    WT_HAS(g_out, "\"label\":\"A7 fanout 203.0.113.50\",\"held\":true");
    WT_HAS(g_out, "\"anomalies\":[{\"id\":\"a");
    env_close();
}
#endif /* WITH_SQLITE: links, candidates, bundle */

/* ── over a socket ──────────────────────────────────────────────────── */

typedef struct {
    web_server_t *s;
    pthread_t     th;
    int           rc;
} running_t;

static void *server_main(void *arg) {
    running_t *r = arg;
    r->rc = web_server_run(r->s);
    return NULL;
}

static int srv_start(running_t *r) {
    web_config_t c;
    web_config_defaults(&c);
    c.bind_port = 0;
    c.timeout_ms = 2000;
    c.linger_ms = 200;
    char err[256];
    r->s = calloc(1, sizeof(*r->s));
    if (!r->s || web_server_open(r->s, &c, err, sizeof(err)) != 0) {
        if (r->s) web_server_close(r->s);
        free(r->s);
        r->s = NULL;
        return -1;
    }
    web_server_set_live(r->s, &E.live);
    web_server_set_m4(r->s, &E.m4);
    if (pthread_create(&r->th, NULL, server_main, r) != 0) return -1;
    return 0;
}

static void srv_stop(running_t *r) {
    web_server_stop(r->s);
    pthread_join(r->th, NULL);
    web_server_close(r->s);
    free(r->s);
    r->s = NULL;
}

static void exchange(uint16_t port, const char *req, size_t len) {
    g_out[0] = '\0';
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct timeval tv = { 4, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
        send(fd, req, len, MSG_NOSIGNAL);
        size_t n = 0;
        while (n + 1 < sizeof(g_out)) {
            ssize_t k = recv(fd, g_out + n, sizeof(g_out) - 1 - n, 0);
            if (k <= 0) break;
            n += (size_t)k;
        }
        g_out[n] = '\0';
    }
    close(fd);
}

/* test_post_over_socket's and test_oversize_body_refused_unread's: the
 * link's write through the real server takes the path the alert's
 * takes. A good one is written; another origin is 403 before the body
 * is read; a body over WEB_POST_MAX is 413 unread; a POST to the read
 * route is the 405 every other path answers. Seen red with
 * "/api/frrs/relate" taken out of web_http.c's POST_PATHS (the good one
 * 405: the server admits a POST nowhere else). */
static void test_relate_over_socket(void) {
    env_open(1);
    running_t r;
    WT_EQ(srv_start(&r), 0);
    if (!r.s) { env_close(); return; }
    uint16_t port = web_server_port(r.s);
    char a[WEB_ANOM_TID_MAX + 1], body[256], req[1024];
    ep(1, "A3", WM_DEV_PRESENT, MAC1, WEB_EP_OPEN, T - 600, T - 60, a);
    int bl = snprintf(body, sizeof(body), "{\"op\":\"add\",\"from\":\"%s\",\"to\":\"" MAC1 "\",\"by\":\"sock\"}", a);
    int hl = snprintf(req, sizeof(req), "POST /api/frrs/relate HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                      "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n"
                      "Content-Length: %d\r\n\r\n%s", port, port, bl, body);
    exchange(port, req, (size_t)hl);
    WT_HAS(g_out, E.have_store ? "HTTP/1.1 200 OK\r\n" : "HTTP/1.1 503");
    if (E.have_store) WT_HAS(g_out, "\"by\":\"sock\"");
    hl = snprintf(req, sizeof(req), "POST /api/frrs/relate HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                  "Origin: http://evil.example\r\nContent-Type: application/json\r\n"
                  "Content-Length: %d\r\n\r\n%s", port, bl, body);
    exchange(port, req, (size_t)hl);
    WT_HAS(g_out, "HTTP/1.1 403");
    WT_HAS(g_out, "bad_origin");
    hl = snprintf(req, sizeof(req), "POST /api/frrs/relate HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                  "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n"
                  "Content-Length: %d\r\n\r\n", port, port, WEB_POST_MAX + 1);
    exchange(port, req, (size_t)hl);
    WT_HAS(g_out, "HTTP/1.1 413 Content Too Large\r\n");
    hl = snprintf(req, sizeof(req), "POST /api/frrs/related HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                  "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n"
                  "Content-Length: 2\r\n\r\n{}", port, port);
    exchange(port, req, (size_t)hl);
    WT_HAS(g_out, "HTTP/1.1 405");
    WT_HAS(g_out, "Allow: GET, HEAD\r\n");
    hl = snprintf(req, sizeof(req), "GET /api/frrs/related?id=%s HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n\r\n",
                  a, port);
    exchange(port, req, (size_t)hl);
    WT_HAS(g_out, "HTTP/1.1 200 OK");
    WT_EQ(count_of(g_out, "{\"link\":"), E.have_store ? 1 : 0);
    srv_stop(&r);
    env_close();
}

/* ── the page ───────────────────────────────────────────────────────── */

/* One function of the module, whole: from its first line to the "  }"
 * that closes it at the module's indent. */
static int has_fn(const char *m, const char *whole) {
    return strstr(m, whole) != NULL;
}

/* test_page_module's, for notes.js: no sink that parses markup, no
 * attribute or link built from a value, the functions that draw
 * operator text and make the writes pinned whole (a line changed
 * inside one fails here, not only the line a single pin would name),
 * the hooks app.js calls, and the containers. Seen red with
 * `li.innerHTML = l.note;` added to listLinks() (the sink list), and
 * with `if (rel.writes)` dropped before the candidate's "link" button
 * (the pinned function). */
static void test_page_module(void) {
    const char *p = (const char *)web_page;
    const char *a = strstr(p, "var SlothNotes = (function () {");
    const char *b = a ? strstr(a, "\n})();") : NULL;
    WT_ASSERT(a != NULL && b != NULL);
    if (!a || !b) return;
    size_t n = (size_t)(b - a);
    char *m = malloc(n + 1);
    if (!m) return;
    memcpy(m, a, n);
    m[n] = '\0';
    static const char *const SINK[] = {
        "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "setAttribute(",
        "eval(", "new Function", ".href =", ".src =", "createElement(", "http://", "https://",
        "window.open", "location.assign", "fetch(",
    };
    for (size_t i = 0; i < sizeof(SINK) / sizeof(SINK[0]); i++) WT_LACKS(m, SINK[i]);
    /* One write path: SlothFrrs's post(), to the two routes. */
    WT_EQ(count_of(m, "F.post("), 2);
    WT_HAS(m, "F.post(\"/api/frrs/triage\", b)");
    WT_HAS(m, "F.post(\"/api/frrs/relate\", body)");
    WT_ASSERT(has_fn(m,
        "  function chipOf(st) {\n"
        "    var c = F.chip(st);\n"
        "    if (st && st.carried && st.state !== \"untriaged\") c.appendChild(el(\"span\", \"d-dim\", \" (earlier episode)\"));\n"
        "    return c;\n"
        "  }\n"));
    WT_ASSERT(has_fn(m,
        "  function card(c, a) {\n"
        "    if (!H || !F || !c || !a || typeof a.tid !== \"string\" || !TID_RE.test(a.tid)) return;\n"
        "    var id = a.tid, line = el(\"div\", \"tri notes-line\");\n"
        "    c.appendChild(line);\n"
        "    if (!S.reg[id]) S.reg[id] = [];\n"
        "    S.reg[id].push({ card: c, line: line });\n"
        "    var t = Date.now();\n"
        "    if (S.seen[id] && t - S.seen[id] < 10000) { setTimeout(function () { render(id); }, 0); return; }\n"
        "    if (S.queue.indexOf(id) < 0) S.queue.push(id);\n"
        "    if (!S.qt) S.qt = setTimeout(flush, 30);\n"
        "  }\n"));
    WT_ASSERT(has_fn(m,
        "  function follow(kind, id, iface) {\n"
        "    if (kind === \"alert\" && ALERT_RE.test(id)) { close(); H.go(\"alert\", { id: id }); }\n"
        "    else if (kind === \"device\" && MAC_RE.test(id)) { close(); H.openDrawer(id); }\n"
        "    else if (kind === \"ble\" && BLE_RE.test(id) && typeof iface === \"string\") {\n"
        "      close();\n"
        "      H.openBleDrawer(id.slice(0, 17), Number(id.slice(18)), iface);\n"
        "    }\n"
        "    else if (kind === \"anomaly\" && TID_RE.test(id)) open(id);\n"
        "  }\n"));
    /* The card's chip, button and dimming, whole. A triaged-out state
     * dims the card whether it was decided on this episode or carried
     * from an earlier one (owner ruling 2026-11-11), the "earlier
     * episode" mark still on it (chipOf(), above); an incident never
     * dims (out()). Seen red with the old rule put back,
     * `out(st.state) && !st.carried`. */
    WT_ASSERT(has_fn(m,
        "  function render(id) {\n"
        "    var places = S.reg[id];\n"
        "    if (!places) return;\n"
        "    var st = S.st[id] || { state: \"untriaged\" };\n"
        "    S.reg[id] = places.filter(function (p) { return p.card && p.card.isConnected; });\n"
        "    if (!S.reg[id].length) { delete S.reg[id]; return; }\n"
        "    S.reg[id].forEach(function (p) {\n"
        "      clear(p.line);\n"
        "      if (st.state !== \"untriaged\") p.line.appendChild(chipOf(st));\n"
        "      p.line.appendChild(btn(st.state === \"untriaged\" ? \"triage\" : \"notes\", \"\", function () { open(id); }));\n"
        "      p.card.classList.toggle(\"tri-out\", out(st.state));\n"
        "    });\n"
        "  }\n"));
    WT_HAS(m, "function out(st) { return st === \"false\" || st === \"noise\" || st === \"known\"; }");
    WT_LACKS(m, "!st.carried");
    /* A panel's form: one link from the panel's subject to what was
     * typed, whole. */
    WT_ASSERT(has_fn(m,
        "  function wire(which, inp, add) {\n"
        "    if (!$(inp) || !$(add)) return;\n"
        "    $(add).addEventListener(\"click\", function () {\n"
        "      var from = S.sub[which], to = typed($(inp)), msg = S.msg[which];\n"
        "      if (!from || !msg) return;\n"
        "      if (!REF_RE.test(to)) { msg.textContent = WHY.bad_id; return; }\n"
        "      var b = { op: \"add\", from: from, to: to };\n"
        "      if (by()) b.by = by();\n"
        "      relate(b, msg, function () { $(inp).value = \"\"; if (S.read[which]) S.read[which](); });\n"
        "    });\n"
        "  }\n"));
    WT_ASSERT(has_fn(m,
        "  function relate(body, msg, then) {\n"
        "    if (msg) msg.textContent = \"pending: not in the store until the server confirms it\";\n"
        "    return F.post(\"/api/frrs/relate\", body).then(function (j) {\n"
        "      if (msg) msg.textContent = \"\";\n"
        "      then(j.related);\n"
        "    }).catch(function (e) {\n"
        "      if (msg) msg.textContent = WHY[e && e.message] || F.why(e);\n"
        "    });\n"
        "  }\n"));
    WT_ASSERT(has_fn(m,
        "  function listLinks(box, sug, rel, from, msg, redraw) {\n"
        "    clear(box);\n"
        "    var links = rel.links || [];\n"
        "    if (!links.length) box.appendChild(el(\"li\", \"sub\", \"no link yet\"));\n"
        "    links.forEach(function (l) {\n"
        "      var li = el(\"li\", \"notes-row\");\n"
        "      li.appendChild(el(\"span\", \"d-dim\", l.dir === \"to\" ? \"to \" + l.kind : \"from \" + l.kind));\n"
        "      li.appendChild(el(\"span\", l.held ? \"d-bright\" : \"d-dim\", l.label || l.id));\n"
        "      if (!l.held) li.appendChild(el(\"span\", \"sev1\", \"no longer held\"));\n"
        "      if (l.triage && l.triage.state !== \"untriaged\") li.appendChild(chipOf(l.triage));\n"
        "      if (l.note) li.appendChild(el(\"span\", \"d-normal\", l.note));\n"
        "      // A link an agent made says so (subnotes.js's mark).\n"
        "      var am = window.SlothSubNotes ? window.SlothSubNotes.agent(l.via) : null;\n"
        "      if (am) li.appendChild(am);\n"
        "      li.appendChild(el(\"span\", \"d-dim\", (l.by || \"-\") + \" \xc2\xb7 from \" + (l.peer || \"?\") + \" \xc2\xb7 \" + H.shortStamp(l.ts)));\n"
        "      if (l.held && (l.kind !== \"ble\" || l.iface)) li.appendChild(btn(\"open\", \"\", function () { follow(l.kind, l.id, l.iface); }));\n"
        "      if (rel.writes) li.appendChild(btn(\"remove\", \"\", function () {\n"
        "        relate({ op: \"remove\", from: from, link: l.link }, msg, redraw);\n"
        "      }));\n"
        "      box.appendChild(li);\n"
        "    });\n"
        "    if (rel.links_more) box.appendChild(el(\"li\", \"sub\", \"more than \" + rel.links_cap + \" links: the newest shown\"));\n"
        "    if (!sug) return;\n"
        "    clear(sug);\n"
        "    var cs = rel.suggest || [];\n"
        "    if (!cs.length) sug.appendChild(el(\"li\", \"sub\", rel.held ? \"none in the window\" : \"none: not held now\"));\n"
        "    cs.forEach(function (c) {\n"
        "      var li = el(\"li\", \"notes-row\");\n"
        "      li.appendChild(el(\"span\", \"d-dim\", c.kind));\n"
        "      li.appendChild(el(\"span\", \"d-bright\", c.label || c.id));\n"
        "      li.appendChild(el(\"span\", \"d-normal\", c.basis));\n"
        "      li.appendChild(el(\"span\", \"d-dim\", H.shortStamp(c.first_seen) + \" to \" + H.shortStamp(c.last_seen)));\n"
        "      li.appendChild(btn(\"open\", \"\", function () { follow(c.kind, c.id); }));\n"
        "      // One action accepts it; until then nothing is stored. An anomaly\n"
        "      // is always the \"from\" end, so an alert's candidate is linked\n"
        "      // from the anomaly to the alert.\n"
        "      if (rel.writes) li.appendChild(btn(\"link\", \"\", function () {\n"
        "        var b = rel.kind === \"anomaly\" ? { op: \"add\", from: from, to: c.id } : { op: \"add\", from: c.id, to: from };\n"
        "        if (by()) b.by = by();\n"
        "        // The answer lists the \"from\" end: an alert's list is read again.\n"
        "        relate(b, msg, rel.kind === \"anomaly\" ? redraw : function () { redraw(null); });\n"
        "      }));\n"
        "      sug.appendChild(li);\n"
        "    });\n"
        "  }\n"));
    WT_ASSERT(has_fn(m,
        "  function act(id, state) {\n"
        "    var n = $(\"notes-note\"), msg = $(\"notes-msg\");\n"
        "    var note = n.value.trim(), m = n.maxLength > 0 ? n.maxLength : 240;\n"
        "    var b = { id: id, state: state };\n"
        "    if (note) b.note = note;\n"
        "    if (by()) b.by = by();\n"
        "    if (note && F.bytes(note) > m) {\n"
        "      msg.textContent = \"note too long: \" + F.bytes(note) + \" of \" + m + \" bytes; nothing was saved\";\n"
        "      return;\n"
        "    }\n"
        "    // Nothing is drawn from the request: the state and the history\n"
        "    // change only once the server has the row.\n"
        "    msg.textContent = \"pending: not in the store until the server confirms it\";\n"
        "    F.post(\"/api/frrs/triage\", b).then(function (j) {\n"
        "      S.st[id] = j.current;\n"
        "      msg.textContent = \"\";\n"
        "      n.value = \"\";\n"
        "      noteCount();\n"
        "      render(id);\n"
        "      load(id);\n"
        "    }).catch(function (e) {\n"
        "      msg.textContent = WHY[e && e.message] || F.why(e);\n"
        "      load(id);\n"
        "    });\n"
        "  }\n"));
    /* The states are the alert's four, and the clear. */
    WT_HAS(m, "var STATES = [\"false\", \"noise\", \"incident\", \"known\"];");
    WT_HAS(m, "bb.appendChild(btn(\"clear\", \"\", function () { act(id, \"untriaged\"); }));");
    WT_HAS(m, "\"decided on an earlier episode (first seen \" + H.stamp(h.current.episode) +");
    free(m);
    /* frrs.js lends its write path and its chip; nothing else of it changed. */
    WT_HAS(p, "           post: post, why: why, chip: chip, bytes: bytes };");
    /* The module sits after frrs.js (whose post it uses) and before
     * app.js (which calls it). */
    const char *fr = strstr(p, "var SlothFrrs = (function () {");
    const char *ap = strstr(p, "if (window.SlothNotes) SlothNotes.init({");
    WT_ASSERT(fr && ap && fr < a && a < ap);
    static const char *const HOOK[] = {
        "    if (window.SlothNotes) SlothNotes.card(c, a);\n    return c;\n  }\n",
        "      if (window.SlothNotes) SlothNotes.drawer(mac);\n",
        "    if (window.SlothNotes) SlothNotes.alert(j);\n",
        "  if (window.SlothNotes) SlothNotes.init({ el: el, getJSON: getJSON, prefGet: prefGet, stamp: stamp,\n"
        "    shortStamp: shortStamp, go: go, openDrawer: openDrawer, openBleDrawer: openBleDrawer });\n",
        /* The Anomalies view's table form: the same chip and panel on
         * every row, so every place an anomaly is listed can be triaged.
         * Seen red with the call taken out of anomTable(). */
        "        row.addEventListener(\"click\", function () { openDrawer(a.key); });\n      }\n"
        "      if (window.SlothNotes) SlothNotes.card(row, a);\n      box.appendChild(row);\n",
        "    if (window.SlothNotes) SlothNotes.ble(addr, type);\n",
    };
    for (size_t i = 0; i < sizeof(HOOK) / sizeof(HOOK[0]); i++) WT_EQ(count_of(p, HOOK[i]), 1);
    WT_EQ(count_of(p, "SlothNotes."), 6 + 6);         /* the hooks, and the module's header naming them */
    WT_HAS(p, ".dt .dt-row > .notes-line { grid-column: 1 / -1; margin-top: 0; }");
    static const char *const IDS[] = {
        "<dialog class=\"notes\" id=\"notes-dlg\"", "id=\"notes-alert\"", "id=\"notes-drawer\"",
        "id=\"notes-btns\"", "id=\"notes-hist\"", "id=\"notes-links\"", "id=\"notes-sugg\"",
        "id=\"notes-to\" maxlength=\"47\"", "id=\"notes-add\"", "id=\"notes-msg\"",
        "id=\"notes-alert-list\"", "id=\"notes-alert-to\" maxlength=\"47\"", "id=\"notes-alert-add\"",
        "id=\"notes-drawer-list\"", "id=\"notes-dev-to\" maxlength=\"47\"", "id=\"notes-dev-add\"",
        "id=\"notes-bdrawer\"", "id=\"notes-bdrawer-list\"", "id=\"notes-ble-to\" maxlength=\"47\"",
        "id=\"notes-ble-add\"",
    };
    for (size_t i = 0; i < sizeof(IDS) / sizeof(IDS[0]); i++) WT_EQ(count_of(p, IDS[i]), 1);
    /* The note field carries the server's own bound, as the alert's does. */
    char ml[96];
    snprintf(ml, sizeof(ml), "id=\"notes-note\" maxlength=\"%d\"", WEB_FRRS_NOTE_MAX);
    WT_HAS(p, ml);
    /* Beside the alert's triage and above the proof; in the drawer
     * after its anomalies. */
    const char *ft = strstr(p, "id=\"frrs-alert-triage\"");
    const char *na = strstr(p, "id=\"notes-alert\"");
    const char *ea = strstr(p, "id=\"ev-alert\"");
    WT_ASSERT(ft && na && ea && ft < na && na < ea);
    const char *da = strstr(p, "id=\"dr-anoms\"");
    const char *nd = strstr(p, "id=\"notes-drawer\"");
    const char *fd = strstr(p, "id=\"frrs-drawer\"");
    WT_ASSERT(da && nd && fd && da < nd && nd < fd);
    WT_HAS(p, "dialog.notes::backdrop");
}

void run_notes_tests(void) {
    WT_RUN(test_page_module);
    WT_RUN(test_anomaly_triage_round_trip);
    WT_RUN(test_anomaly_states);
    WT_RUN(test_anomaly_cross_origin_refused);
    WT_RUN(test_anomaly_body_rules);
    WT_RUN(test_anomaly_note_over_limit);
    WT_RUN(test_anomaly_get_cannot_write);
    WT_RUN(test_anomaly_read_only);
#ifdef WITH_SQLITE
    WT_RUN(test_links_both_directions);
    WT_RUN(test_link_guards);
    WT_RUN(test_alert_device_links);
    WT_RUN(test_ble_links);
    WT_RUN(test_ids_beginning_d);
    WT_RUN(test_nothing_from_the_stream_stored);
    WT_RUN(test_anomaly_unchanged_write_adds_no_row);
    WT_RUN(test_anomaly_history_folds);
    WT_RUN(test_anomaly_cap_keeps_current_rows);
    WT_RUN(test_anomaly_survives_reopen_and_redetection);
    WT_RUN(test_anomaly_id_collision_refused);
    WT_RUN(test_alert_and_anomaly_rows_apart);
    WT_RUN(test_fleet_verdicts_are_alerts_only);
    WT_RUN(test_dangling_target);
    WT_RUN(test_suggestions);
    WT_RUN(test_suggestions_stay_inside_the_budget);
    WT_RUN(test_bundle_carries_links_and_anomaly_triage);
#endif
    WT_RUN(test_relate_over_socket);
}
