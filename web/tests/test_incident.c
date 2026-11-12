/* Many alerts triaged as one (#198): POST /api/frrs/triage/bulk and
 * the incidents (web_incident.c). The world is test_notes.c's: a store
 * in a fresh directory, the demo's sloth.db and stream.
 *
 * Every absence assertion here was seen red under the mutation its
 * comment names, in this tree, the source restored and the suite run
 * green again afterwards. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_assets.h"
#include "web_frrs.h"
#include "web_incident.h"
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
#define SECRET "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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
    web_m4_t       m4;
    web_health_t   h;
} env_t;
static env_t E;

#ifdef WITH_SQLITE
static void env_open(int writes) {
    char err[512];
    memset(&E, 0, sizeof(E));
    snprintf(E.dir, sizeof(E.dir), "%s/slothweb-inc-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(E.dir) != NULL);
    snprintf(E.store_path, sizeof(E.store_path), "%s/slothweb.db", E.dir);
    snprintf(E.sdb_path, sizeof(E.sdb_path), "%s/sloth.db", E.dir);
    if (web_store_available()) {
        WT_EQ(web_store_open(&E.store, E.store_path, err, sizeof(err)), 0);
        E.have_store = 1;
    }
    WT_EQ(web_frrs_init(&E.f, E.have_store ? &E.store : NULL, NULL, writes, err, sizeof(err)), 0);
    web_frrs_set_agent(&E.f, SECRET);
    E.m4.frrs = &E.f;
    web_live_init(&E.live, "unix:/demo/sloth.sock");
    web_live_sock_connected(&E.live, 0);
    E.have_db = web_store_available() && demo_make_db(E.sdb_path, T) == 0;
    web_sdb_fns_t fns = { NULL, NULL, NULL, &E.live };
    web_slothdb_init(&E.sdb, E.have_db ? E.sdb_path : "", &fns);
    E.m4.sdb = E.have_db ? &E.sdb : NULL;
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
    web_frrs_destroy(&E.f);
    web_slothdb_destroy(&E.sdb);
    web_live_destroy(&E.live);
    web_store_close(&E.store);
    test_rm_tree(E.dir);
}

#endif

static void base_rq(web_req_t *rq, const char *path, const char *query) {
    memset(rq, 0, sizeof(*rq));
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query ? query : "");
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    rq->content_length = -1;
    snprintf(rq->peer, sizeof(rq->peer), "127.0.0.1");
}

static int route(web_req_t *rq) {
    web_resp_t r;
    memset(&r, 0, sizeof(r));
    if (web_route(rq, &E.h, 1, g_out, sizeof(g_out), &r) != 0) return -1;
    size_t n = r.out_len < sizeof(g_out) - 1 ? r.out_len : sizeof(g_out) - 1;
    if (r.body && r.body_len && n + r.body_len < sizeof(g_out) - 1) {
        memcpy(g_out + n, r.body, r.body_len);
        n += r.body_len;
    }
    g_out[n] = '\0';
    if (r.body_free) free((void *)r.body);
    free(r.body_owned);
    return r.status;
}

static int get(const char *path, const char *query) {
    web_req_t rq;
    base_rq(&rq, path, query);
    return route(&rq);
}

/* A POST as the page sends one (agent 0) or as slothweb-mcp does (agent
 * 1: the secret, no Origin). tick: the clock moves two seconds first,
 * one token's refill, so a test that is not about the bucket never
 * meets it. */
static int post_as(const char *path, const char *body, int agent, int tick) {
    web_req_t rq;
    base_rq(&rq, path, "");
    rq.is_post = 1;
    if (agent) {
        snprintf(rq.agent, sizeof(rq.agent), "%s", SECRET);
        rq.agent_count = 1;
    } else {
        snprintf(rq.origin, sizeof(rq.origin), "http://127.0.0.1:8770");
        rq.origin_count = 1;
    }
    snprintf(rq.ctype, sizeof(rq.ctype), "application/json");
    rq.ctype_count = 1;
    rq.body = body;
    rq.body_len = strlen(body);
    rq.content_length = (long long)rq.body_len;
    if (tick) E.h.now_ms += 2000;
    return route(&rq);
}
static int post(const char *path, const char *body) { return post_as(path, body, 0, 1); }

#ifdef WITH_SQLITE
static int apost(const char *path, const char *body) { return post_as(path, body, 1, 1); }

static int count_of(const char *s, const char *w) {
    int n = 0;
    for (const char *q = strstr(s, w); q; q = strstr(q + 1, w)) n++;
    return n;
}

static long long json_int(const char *b, const char *key) {
    char k[64];
    snprintf(k, sizeof(k), "\"%s\":", key);
    const char *p = strstr(b, k);
    return p ? atoll(p + strlen(k)) : -1;
}

#endif

/* ── the routes without a store ────────────────────────────────────── */

/* No store (WITH_SQLITE=0, or the store not open): every write is 503
 * no_store, the list answers empty, one incident is 503. */
static void test_without_a_store(void) {
    char err[512];
    memset(&E, 0, sizeof(E));
    WT_EQ(web_frrs_init(&E.f, NULL, NULL, 1, err, sizeof(err)), 0);
    E.m4.frrs = &E.f;
    E.h.wall_s = T;
    E.h.now_ms = 30000;
    E.h.m4 = &E.m4;
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"add\",\"title\":\"x\",\"state\":\"noise\"}"), 503);
    WT_HAS(body_of(g_out), "\"error\":\"no_store\"");
    WT_EQ(post("/api/frrs/triage/bulk", "{\"ids\":\"d1\",\"state\":\"noise\"}"), 503);
    WT_EQ(get("/api/frrs/incidents", ""), 200);
    WT_HAS(body_of(g_out), "\"store\":\"none\"");
    WT_HAS(body_of(g_out), "\"incidents\":[],\"more\":false}");
    WT_EQ(get("/api/frrs/incidents", "state=bogus"), 400);
    WT_EQ(get("/api/frrs/incidents", "id=1"), 503);
    /* A GET at the write path, a POST at the read path: neither. */
    WT_EQ(get("/api/frrs/incident", ""), 405);
    WT_EQ(post("/api/frrs/incidents", "{}"), 405);
    web_frrs_destroy(&E.f);
}

#ifdef WITH_SQLITE

/* The /api/alerts rows' ids (closed and open), up to max, and each
 * one's type name. */
static int alert_ids(char ids[][32], char types[][48], int max) {
    int n = 0;
    if (get("/api/alerts", "limit=100") != 200) return 0;
    const char *b = body_of(g_out);
    for (const char *p = strstr(b, "{\"id\":\""); p && n < max; p = strstr(p + 1, "{\"id\":\"")) {
        const char *e = strchr(p + 7, '"');
        const char *t = strstr(p, "\"type_name\":\"");
        if (!e || !t || e - p - 7 >= 32) continue;
        snprintf(ids[n], 32, "%.*s", (int)(e - p - 7), p + 7);
        t += 13;
        const char *te = strchr(t, '"');
        snprintf(types[n], 48, "%.*s", te ? (int)(te - t) : 0, t);
        n++;
    }
    return n;
}

static long long store_int(const char *sql) {
    sqlite3 *h = NULL;
    long long v = -1;
    if (sqlite3_open_v2(E.store_path, &h, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
            v = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    sqlite3_close(h);
    return v;
}

/* The answer's text from `from` up to the next "}" at its own depth, as
 * a copy: one alert's entry of /api/frrs/states. */
static const char *entry(const char *b, const char *id) {
    static char out[4096];
    char k[48];
    snprintf(k, sizeof(k), "\"%s\":{", id);
    const char *p = strstr(b, k);
    out[0] = '\0';
    if (!p) return out;
    int d = 0;
    const char *q = p + strlen(k) - 1;
    for (; *q; q++) {
        if (*q == '{') d++;
        if (*q == '}' && --d == 0) break;
    }
    snprintf(out, sizeof(out), "%.*s", (int)(q - p + 1), p);
    return out;
}

/* ── bulk triage ───────────────────────────────────────────────────── */

/* One verdict on many ids: each written as POST /api/frrs/triage would
 * write it (a row, its history, via, by), a failing id reported in its
 * place while the others go on, a repeat "unchanged" with no row, and
 * the list held to its bounds whole. Seen red with tri_apply()'s
 * failure made to end the loop (`break` for `continue`: the ids after
 * the bad one were never written). */
static void test_bulk_triage(void) {
    env_open(1);
    if (!E.have_store || !E.have_db) { env_close(); return; }
    char ids[8][32], ty[8][48];
    int n = alert_ids(ids, ty, 8);
    WT_ASSERT(n >= 4);
    if (n < 4) { env_close(); return; }
    char b[1024];
    snprintf(b, sizeof(b), "{\"ids\":\"%s,d999999,%s,%s\",\"state\":\"noise\",\"note\":\"rv park\","
             "\"by\":\"op\"}", ids[0], ids[1], ids[2]);
    WT_EQ(post("/api/frrs/triage/bulk", b), 200);
    const char *a = body_of(g_out);
    WT_HAS(a, "{\"ok\":true,\"state\":\"noise\",\"n\":4,\"results\":[");
    WT_HAS(a, "{\"id\":\"d999999\",\"ok\":false,\"status\":404,\"error\":\"no_such_alert\"}");
    WT_EQ(json_int(a, "written"), 3);
    WT_EQ(json_int(a, "failed"), 1);
    WT_EQ(count_of(a, "\"ok\":true,\"unchanged\":false,\"current\":{\"state\":\"noise\""), 3);
    WT_EQ(store_int("SELECT COUNT(*) FROM triage WHERE state = 2 AND note = 'rv park' AND"
                    " who = 'op' AND via = 0"), 3);
    /* The same again: nothing new to say, no row. */
    WT_EQ(post("/api/frrs/triage/bulk", b), 200);
    WT_HAS(body_of(g_out), "],\"written\":0,\"unchanged\":3,\"failed\":1}");
    WT_EQ(store_int("SELECT COUNT(*) FROM triage"), 3);
    /* Each one reads as written through the single routes. */
    char q[128];
    snprintf(q, sizeof(q), "ids=%s,%s", ids[0], ids[2]);
    WT_EQ(get("/api/frrs/states", q), 200);
    WT_HAS(entry(body_of(g_out), ids[0]), "\"state\":\"noise\"");
    WT_HAS(entry(body_of(g_out), ids[2]), "\"note\":\"rv park\"");
    /* A repeated id is one. */
    snprintf(b, sizeof(b), "{\"ids\":\"%s,%s\",\"state\":\"false\"}", ids[3], ids[3]);
    WT_EQ(post("/api/frrs/triage/bulk", b), 200);
    WT_HAS(body_of(g_out), "\"n\":1,");
    /* The list's bounds, each refused whole before anything is written. */
    long long rows = store_int("SELECT COUNT(*) FROM triage");
    char big[4096];
    size_t o = (size_t)snprintf(big, sizeof(big), "{\"ids\":\"");
    for (int i = 0; i < WEB_FRRS_BULK_MAX + 1; i++)
        o += (size_t)snprintf(big + o, sizeof(big) - o, "%sd%d", i ? "," : "", i + 1);
    snprintf(big + o, sizeof(big) - o, "\",\"state\":\"noise\"}");
    WT_EQ(post("/api/frrs/triage/bulk", big), 400);
    WT_HAS(body_of(g_out), "\"error\":\"too_many_ids\"");
    static const char *const BAD[] = {
        "{\"ids\":\"d1,<script>\",\"state\":\"noise\"}", "{\"ids\":\"d1,,d2\",\"state\":\"noise\"}",
        "{\"ids\":\"d1,\",\"state\":\"noise\"}", "{\"ids\":\"x1\",\"state\":\"noise\"}",
        "{\"ids\":\"d1 \",\"state\":\"noise\"}",
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        WT_EQ(post("/api/frrs/triage/bulk", BAD[i]), 400);
        WT_HAS(body_of(g_out), "\"error\":\"bad_ids\"");
    }
    WT_EQ(post("/api/frrs/triage/bulk", "{\"ids\":\"\",\"state\":\"noise\"}"), 400);
    WT_HAS(body_of(g_out), "\"error\":\"missing_ids\"");
    snprintf(b, sizeof(b), "{\"ids\":\"%s\",\"state\":\"maybe\"}", ids[0]);
    WT_EQ(post("/api/frrs/triage/bulk", b), 400);
    WT_HAS(body_of(g_out), "\"error\":\"bad_state\"");
    snprintf(b, sizeof(b), "{\"ids\":\"%s\",\"state\":\"noise\",\"id\":\"%s\"}", ids[0], ids[0]);
    WT_EQ(post("/api/frrs/triage/bulk", b), 400);
    WT_HAS(body_of(g_out), "\"error\":\"unknown_member\",\"member\":\"id\"");
    /* The 240-byte note rule, as the single route has it. */
    char note[260];
    memset(note, 'n', 241);
    note[241] = '\0';
    snprintf(big, sizeof(big), "{\"ids\":\"%s\",\"state\":\"noise\",\"note\":\"%s\"}", ids[0], note);
    WT_EQ(post("/api/frrs/triage/bulk", big), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"too_long\",\"member\":\"note\",\"length\":241,\"limit\":240}");
    WT_EQ(store_int("SELECT COUNT(*) FROM triage"), rows);
    env_close();
}

/* One bulk POST is one token, whatever it carries: the bucket's burst
 * of ten takes ten bulk POSTs of twenty ids each (two hundred rows),
 * the eleventh is 429 with a Retry-After and writes nothing. Seen red
 * with the gate's cost made the id count (the second POST was refused). */
static void test_bulk_costs_one_token(void) {
    env_open(1);
    if (!E.have_store || !E.have_db) { env_close(); return; }
    char ids[24][32], ty[24][48];
    int n = alert_ids(ids, ty, 24);
    WT_ASSERT(n >= 2);
    if (n < 2) { env_close(); return; }
    char b[2048];
    for (int k = 0; k < WEB_FRRS_RATE_BURST; k++) {
        size_t o = (size_t)snprintf(b, sizeof(b), "{\"ids\":\"");
        for (int i = 0; i < 20; i++)
            o += (size_t)snprintf(b + o, sizeof(b) - o, "%s%s", i ? "," : "", i < n ? ids[i] : ids[0]);
        snprintf(b + o, sizeof(b) - o, "\",\"state\":\"%s\"}", k % 2 ? "noise" : "false");
        WT_EQ(post_as("/api/frrs/triage/bulk", b, 0, 0), 200);
    }
    long long rows = store_int("SELECT COUNT(*) FROM triage");
    WT_EQ(post_as("/api/frrs/triage/bulk", b, 0, 0), 429);
    WT_HAS(g_out, "Retry-After: ");
    WT_HAS(body_of(g_out), "{\"error\":\"rate_limited\"}");
    WT_EQ(store_int("SELECT COUNT(*) FROM triage"), rows);
    WT_EQ(get("/api/health", ""), 200);
    WT_HAS(body_of(g_out), "\"bulk_posts\":10,");
    WT_HAS(body_of(g_out), "\"rate_limited\":1,");
    /* The agent's own bucket: the operator's spent one is not its. */
    snprintf(b, sizeof(b), "{\"ids\":\"%s\",\"state\":\"noise\",\"by\":\"claw\"}", ids[0]);
    WT_EQ(post_as("/api/frrs/triage/bulk", b, 1, 0), 200);
    WT_EQ(store_int("SELECT COUNT(*) FROM triage WHERE via = 3 AND who = 'claw'"),
          store_int("SELECT COUNT(*) FROM triage WHERE via = 3"));
    env_close();
}

/* ── the incidents ─────────────────────────────────────────────────── */

/* An incident by ids: each member reads its state on every triage
 * route, marked with the incident; the Alerts page's incident= and
 * triage= filters see it; a removed member reads as itself again; an
 * id that is no alert is that id's entry, the others filed. Seen red
 * with frrs_inc_overlay() returning 0 at once (the states entry read
 * untriaged). */
static void test_incident_by_ids(void) {
    env_open(1);
    if (!E.have_store || !E.have_db) { env_close(); return; }
    char ids[8][32], ty[8][48];
    int n = alert_ids(ids, ty, 8);
    WT_ASSERT(n >= 3);
    if (n < 3) { env_close(); return; }
    char b[1024], q[160];
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"title\":\"own test campaign\",\"state\":\"known\","
             "\"note\":\"nmap from the laptop\",\"by\":\"op\",\"ids\":\"%s,%s,d999999\"}",
             ids[0], ids[1]);
    WT_EQ(post("/api/frrs/incident", b), 200);
    const char *a = body_of(g_out);
    WT_HAS(a, "{\"ok\":true,\"op\":\"add\",\"unchanged\":false,\"incident\":{\"id\":1,"
              "\"title\":\"own test campaign\",\"state\":\"known\",\"open\":true,");
    WT_HAS(a, "\"alerts\":2,\"filters\":0}");
    WT_HAS(a, "{\"id\":\"d999999\",\"ok\":false,\"status\":404,\"error\":\"no_such_alert\"}");
    WT_EQ(count_of(a, "\"ok\":true,\"unchanged\":false,\"member\":"), 2);
    WT_EQ(store_int("SELECT COUNT(*) FROM triage"), 0);       /* nothing copied into triage */
    snprintf(q, sizeof(q), "ids=%s,%s", ids[0], ids[2]);
    WT_EQ(get("/api/frrs/states", q), 200);
    const char *e0 = entry(body_of(g_out), ids[0]);
    WT_HAS(e0, "\"state\":\"known\"");
    WT_HAS(e0, "\"note\":\"nmap from the laptop\"");
    WT_HAS(e0, "\"incident\":{\"id\":1,\"title\":\"own test campaign\",\"state\":\"known\","
               "\"governs\":true,\"joined\":\"member\",\"auto\":false}");
    WT_HAS(body_of(g_out), "\"untriaged\":[\"");
    WT_LACKS(entry(body_of(g_out), ids[2]), "\"incident\"");
    snprintf(q, sizeof(q), "id=%s", ids[1]);
    WT_EQ(get("/api/frrs/history", q), 200);
    WT_HAS(body_of(g_out), "\"current\":{\"state\":\"known\"");
    WT_HAS(body_of(g_out), "\"rows\":[]");
    /* The Alerts page: triage=known holds the two, incident=1 is them,
     * incident=none the rest. */
    WT_EQ(get("/api/alerts", "limit=100&triage=known"), 200);
    WT_EQ(json_int(body_of(g_out), "total"), 2);
    WT_HAS(body_of(g_out), "\"incident\":{\"id\":1,\"governs\":true,\"auto\":false}");
    WT_EQ(get("/api/alerts", "limit=100&incident=1"), 200);
    WT_EQ(json_int(body_of(g_out), "total"), 2);
    long long all = (get("/api/alerts", "limit=100&triage=any"), json_int(body_of(g_out), "total"));
    WT_EQ(get("/api/alerts", "limit=100&incident=none"), 200);
    WT_EQ(json_int(body_of(g_out), "total"), all - 2);
    WT_EQ(get("/api/alerts", "incident=0"), 400);
    WT_HAS(body_of(g_out), "bad_incident");
    /* The same ids again: unchanged, no row. */
    snprintf(b, sizeof(b), "{\"op\":\"member\",\"incident\":1,\"ids\":\"%s\"}", ids[0]);
    WT_EQ(post("/api/frrs/incident", b), 200);
    WT_HAS(body_of(g_out), "\"ok\":true,\"unchanged\":true,\"member\":1}");
    WT_EQ(store_int("SELECT COUNT(*) FROM incident_member"), 2);
    /* One taken back: a row, and the alert reads as itself again. */
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"member\",\"incident\":1,\"remove\":1}"), 200);
    WT_HAS(body_of(g_out), "\"alerts\":1,");
    WT_EQ(store_int("SELECT COUNT(*) FROM incident_member WHERE removes = 1"), 1);
    snprintf(q, sizeof(q), "ids=%s", ids[0]);
    WT_EQ(get("/api/frrs/states", q), 200);
    WT_LACKS(body_of(g_out), "\"incident\"");
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"member\",\"incident\":1,\"remove\":1}"), 200);
    WT_HAS(body_of(g_out), "\"unchanged\":true");
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"member\",\"incident\":1,\"remove\":99}"), 404);
    WT_HAS(body_of(g_out), "no_such_member");
    /* One incident, read whole. */
    WT_EQ(get("/api/frrs/incidents", "id=1"), 200);
    WT_HAS(body_of(g_out), "\"members\":[{\"member\":2,\"kind\":\"alert\",\"id\":\"");
    WT_HAS(body_of(g_out), "\"more\":false,\"removed\":1}");
    WT_EQ(get("/api/frrs/incidents", "id=2"), 404);
    WT_EQ(get("/api/frrs/incidents", "id=01"), 400);
    WT_EQ(get("/api/frrs/incidents", ""), 200);
    WT_HAS(body_of(g_out), "\"incidents\":[{\"id\":1,");
    WT_EQ(get("/api/frrs/incidents", "state=closed"), 200);
    WT_HAS(body_of(g_out), "\"incidents\":[]");
    env_close();
}

/* What a member reads as (web_incident.h): its own decision at or after
 * the incident's stands; its own clear returns it to the incident; the
 * incident's later close governs again. Seen red with the precedence's
 * `>=` made `>` (the same-second own decision read as the incident's)
 * and with the clear counted as a decision (the cleared alert read
 * untriaged). */
static void test_precedence(void) {
    env_open(1);
    if (!E.have_store || !E.have_db) { env_close(); return; }
    char ids[4][32], ty[4][48];
    int n = alert_ids(ids, ty, 4);
    WT_ASSERT(n >= 2);
    if (n < 2) { env_close(); return; }
    char b[512], q[96];
    snprintf(q, sizeof(q), "ids=%s", ids[0]);
    /* An own decision before the incident: the incident governs. */
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"incident\",\"note\":\"looked real\"}", ids[0]);
    WT_EQ(post("/api/frrs/triage", b), 200);
    E.h.wall_s = T + 10;
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"title\":\"neighbour AP\",\"state\":\"known\","
             "\"ids\":\"%s,%s\"}", ids[0], ids[1]);
    WT_EQ(post("/api/frrs/incident", b), 200);
    WT_EQ(get("/api/frrs/states", q), 200);
    WT_HAS(entry(body_of(g_out), ids[0]), "{\"state\":\"known\",\"ts\":");
    WT_HAS(entry(body_of(g_out), ids[0]), "\"prev_state\":\"incident\"");
    WT_HAS(entry(body_of(g_out), ids[0]), "\"governs\":true");
    /* Its own, in the same second as the incident: its own stands. */
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"false\"}", ids[0]);
    WT_EQ(post("/api/frrs/triage", b), 200);
    WT_HAS(body_of(g_out), "\"current\":{\"state\":\"false\"");
    WT_HAS(body_of(g_out), "\"governs\":false");
    WT_EQ(get("/api/frrs/states", q), 200);
    WT_HAS(entry(body_of(g_out), ids[0]), "{\"state\":\"false\",");
    /* Cleared: back to the incident's. */
    E.h.wall_s = T + 20;
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"untriaged\"}", ids[0]);
    WT_EQ(post("/api/frrs/triage", b), 200);
    WT_HAS(body_of(g_out), "\"current\":{\"state\":\"known\"");
    /* Own again, later; then the incident closes later still, as noise:
     * the close is its decision and governs. */
    E.h.wall_s = T + 30;
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"incident\"}", ids[0]);
    WT_EQ(post("/api/frrs/triage", b), 200);
    E.h.wall_s = T + 40;
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"close\",\"incident\":1,\"state\":\"noise\","
                                     "\"note\":\"rf background\"}"), 200);
    WT_HAS(body_of(g_out), "\"state\":\"noise\",\"open\":false,\"decided\":");
    WT_EQ(get("/api/frrs/states", q), 200);
    WT_HAS(entry(body_of(g_out), ids[0]), "{\"state\":\"noise\",");
    WT_HAS(entry(body_of(g_out), ids[0]), "\"note\":\"rf background\"");
    /* Closed is final: no member change; a second close is unchanged. */
    snprintf(b, sizeof(b), "{\"op\":\"member\",\"incident\":1,\"ids\":\"%s\"}", ids[1]);
    WT_EQ(post("/api/frrs/incident", b), 409);
    WT_HAS(body_of(g_out), "incident_closed");
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"close\",\"incident\":1}"), 200);
    WT_HAS(body_of(g_out), "\"unchanged\":true");
    WT_EQ(store_int("SELECT COUNT(*) FROM incident WHERE closes = 1"), 1);
    /* Two incidents: the one decided last. */
    E.h.wall_s = T + 50;
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"title\":\"second\",\"state\":\"false\",\"ids\":\"%s\"}",
             ids[1]);
    WT_EQ(post("/api/frrs/incident", b), 200);
    snprintf(q, sizeof(q), "ids=%s", ids[1]);
    WT_EQ(get("/api/frrs/states", q), 200);
    WT_HAS(entry(body_of(g_out), ids[1]), "\"incident\":{\"id\":3,");
    env_close();
}

/* A standing filter: an alert of its type joins whatever its id, one
 * that began after the filter was set is "auto-joined", one that began
 * after the close does not join, a window holds to its ends, and the
 * filter's rules (one address, a known type, a window in order, at most
 * WEB_INC_FILTERS) are each refused by name. Seen red with the close
 * clause taken out of BY_FILTER (the closed incident took an alert that
 * began after it). */
static void test_filter_auto_join(void) {
    env_open(1);
    if (!E.have_store || !E.have_db) { env_close(); return; }
    char ids[8][32], ty[8][48];
    int n = alert_ids(ids, ty, 8);
    WT_ASSERT(n >= 1);
    if (n < 1) { env_close(); return; }
    char b[512], q[96];
    snprintf(q, sizeof(q), "ids=%s", ids[0]);
    WT_EQ(get("/api/frrs/history", "id=x"), 404);
    snprintf(q, sizeof(q), "id=%s", ids[0]);
    WT_EQ(get("/api/frrs/history", q), 200);
    long long first = json_int(strstr(body_of(g_out), "\"descriptor\":"), "first_seen");
    WT_ASSERT(first > 0);
    /* Set long before the alert began: it joins, auto. */
    E.h.wall_s = first - 1000;
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"title\":\"%s storm\",\"state\":\"noise\",\"type\":\"%s\"}",
             ty[0], ty[0]);
    WT_EQ(post("/api/frrs/incident", b), 200);
    WT_HAS(body_of(g_out), "\"alerts\":0,\"filters\":1}");
    E.h.wall_s = T;
    snprintf(q, sizeof(q), "ids=%s", ids[0]);
    WT_EQ(get("/api/frrs/states", q), 200);
    WT_HAS(entry(body_of(g_out), ids[0]), "\"governs\":true,\"joined\":\"filter\",\"auto\":true}");
    /* Set after it began: a member, not auto. */
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"title\":\"later\",\"state\":\"false\",\"type\":\"%s\"}",
             ty[0]);
    WT_EQ(post("/api/frrs/incident", b), 200);
    WT_EQ(get("/api/frrs/states", q), 200);
    WT_HAS(entry(body_of(g_out), ids[0]), "\"incident\":{\"id\":2,");
    WT_HAS(entry(body_of(g_out), ids[0]), "\"joined\":\"filter\",\"auto\":false}");
    /* Closed before the alert began: it takes it no more. Both closed
     * the same way, the alert is in neither. */
    E.h.wall_s = first - 500;
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"close\",\"incident\":1}"), 200);
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"close\",\"incident\":2}"), 200);
    E.h.wall_s = T;
    WT_EQ(get("/api/frrs/states", q), 200);
    WT_LACKS(body_of(g_out), "\"incident\"");
    /* A window that ends before the alert began holds nothing; one
     * around it holds it. */
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"title\":\"w\",\"state\":\"noise\",\"from\":1,\"to\":%lld}",
             first - 1);
    WT_EQ(post("/api/frrs/incident", b), 200);
    WT_EQ(get("/api/frrs/states", q), 200);
    WT_LACKS(body_of(g_out), "\"incident\"");
    snprintf(b, sizeof(b), "{\"op\":\"member\",\"incident\":5,\"from\":%lld,\"to\":%lld}", first,
             first);
    WT_EQ(post("/api/frrs/incident", b), 200);
    WT_EQ(get("/api/frrs/states", q), 200);
    WT_HAS(entry(body_of(g_out), ids[0]), "\"incident\":{\"id\":5,");
    /* The same filter twice is one. */
    WT_EQ(post("/api/frrs/incident", b), 200);
    WT_HAS(body_of(g_out), "\"unchanged\":true");
    /* The filter's rules. */
    static const struct { const char *body, *why; } BAD[] = {
        { "{\"op\":\"member\",\"incident\":5,\"ip\":\"10.0.0.1\",\"mac\":\"02:00:00:00:00:01\"}", "one_address" },
        { "{\"op\":\"member\",\"incident\":5,\"type\":\"NOT_A_TYPE\"}", "bad_type" },
        { "{\"op\":\"member\",\"incident\":5,\"ip\":\"10.0.0\"}", "bad_ip" },
        { "{\"op\":\"member\",\"incident\":5,\"mac\":\"02:00:00:00:00\"}", "bad_mac" },
        { "{\"op\":\"member\",\"incident\":5,\"from\":9,\"to\":8}", "bad_window" },
        { "{\"op\":\"member\",\"incident\":5,\"from\":-1}", "bad_from" },
        { "{\"op\":\"member\",\"incident\":5}", "one_change" },
        { "{\"op\":\"member\",\"incident\":5,\"ids\":\"d1\",\"type\":\"PORT_SCAN\"}", "one_change" },
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        WT_EQ(post("/api/frrs/incident", BAD[i].body), 400);
        WT_HAS(body_of(g_out), BAD[i].why);
    }
    /* At most WEB_INC_FILTERS live filters: two are live, six more fit. */
    for (int i = 0; i < WEB_INC_FILTERS - 2; i++) {
        snprintf(b, sizeof(b), "{\"op\":\"member\",\"incident\":5,\"ip\":\"10.9.0.%d\"}", i + 1);
        WT_EQ(post("/api/frrs/incident", b), 200);
    }
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"member\",\"incident\":5,\"ip\":\"10.9.1.1\"}"), 507);
    WT_HAS(body_of(g_out), "filters_full");
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"member\",\"incident\":5,\"ip\":\"10.9.0.1\"}"), 200);
    WT_HAS(body_of(g_out), "\"unchanged\":true");
    env_close();
}

/* The agent's path: an agent opens incidents (via agent, by its name),
 * adds members to any open one, removes only members an agent added and
 * closes only incidents an agent opened. Seen red with each of the two
 * via tests taken out of web_incident_post() (the operator's member was
 * removed, the operator's incident closed). */
static void test_agent_rules(void) {
    env_open(1);
    if (!E.have_store || !E.have_db) { env_close(); return; }
    char ids[4][32], ty[4][48];
    int n = alert_ids(ids, ty, 4);
    WT_ASSERT(n >= 2);
    if (n < 2) { env_close(); return; }
    char b[512];
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"title\":\"operator's\",\"state\":\"known\",\"ids\":\"%s\"}",
             ids[0]);
    WT_EQ(post("/api/frrs/incident", b), 200);
    /* No name: refused, as every agent write. */
    WT_EQ(apost("/api/frrs/incident", "{\"op\":\"close\",\"incident\":1}"), 400);
    WT_HAS(body_of(g_out), "missing_by");
    WT_EQ(apost("/api/frrs/incident", "{\"op\":\"close\",\"incident\":1,\"by\":\"claw\"}"), 403);
    WT_HAS(body_of(g_out), "{\"error\":\"not_agent_incident\",\"member\":\"incident\"}");
    WT_EQ(apost("/api/frrs/incident", "{\"op\":\"member\",\"incident\":1,\"remove\":1,\"by\":\"claw\"}"), 403);
    WT_HAS(body_of(g_out), "not_agent_member");
    snprintf(b, sizeof(b), "{\"op\":\"member\",\"incident\":1,\"ids\":\"%s\",\"by\":\"claw\"}", ids[1]);
    WT_EQ(apost("/api/frrs/incident", b), 200);
    WT_EQ(apost("/api/frrs/incident", "{\"op\":\"member\",\"incident\":1,\"remove\":2,\"by\":\"claw\"}"), 200);
    WT_EQ(store_int("SELECT COUNT(*) FROM incident_member WHERE removes = 2 AND via = 3 AND"
                    " who = 'claw'"), 1);
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"title\":\"agent's\",\"state\":\"noise\",\"by\":\"claw\","
             "\"ids\":\"%s\"}", ids[1]);
    WT_EQ(apost("/api/frrs/incident", b), 200);
    WT_HAS(body_of(g_out), "\"by\":\"claw\",\"peer\":\"127.0.0.1\",\"via\":\"agent\"");
    WT_EQ(apost("/api/frrs/incident", "{\"op\":\"close\",\"incident\":2,\"by\":\"claw\"}"), 200);
    WT_HAS(body_of(g_out), "\"open\":false");
    /* The page closes any. */
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"close\",\"incident\":1}"), 200);
    WT_EQ(get("/api/health", ""), 200);
    WT_HAS(body_of(g_out), "\"incidents\":{\"rows\":2,\"opened\":2,\"closed\":2}");
    env_close();
}

/* Text: a title, a note and a name are kept as the bytes sent and come
 * back as JSON strings, never as markup; a control or bidirectional
 * control is refused; over-long is refused with its length; every op's
 * members are its own. */
static void test_hostile_text(void) {
    env_open(1);
    if (!E.have_store) { env_close(); return; }
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"add\",\"title\":\"<img src=x onerror=alert(1)> \\\"q\\\"\","
                                     "\"state\":\"false\",\"note\":\"</script><b>\",\"by\":\"<i>\"}"), 200);
    /* JSON, and the page's own escape of markup characters (web_json.h). */
    WT_HAS(body_of(g_out), "\"title\":\"\\u003cimg src=x onerror=alert(1)\\u003e \\\"q\\\"\"");
    WT_LACKS(body_of(g_out), "<img");
    WT_HAS(g_out, "Content-Type: application/json");
    WT_EQ(store_int("SELECT COUNT(*) FROM incident WHERE title = '<img src=x onerror=alert(1)> \"q\"'"
                    " AND note = '</script><b>' AND who = '<i>'"), 1);
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"add\",\"title\":\"a\\u202eb\",\"state\":\"false\"}"), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"bad_text\",\"member\":\"title\"}");
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"add\",\"title\":\"a\\nb\",\"state\":\"false\"}"), 400);
    char t[200], b[400];
    memset(t, 't', WEB_INC_TITLE_MAX + 1);
    t[WEB_INC_TITLE_MAX + 1] = '\0';
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"title\":\"%s\",\"state\":\"false\"}", t);
    WT_EQ(post("/api/frrs/incident", b), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"too_long\",\"member\":\"title\",\"length\":97,\"limit\":96}");
    static const struct { const char *body, *why; } BAD[] = {
        { "{\"op\":\"add\",\"state\":\"false\"}", "missing_title" },
        { "{\"op\":\"add\",\"title\":\"x\"}", "missing_state" },
        { "{\"op\":\"add\",\"title\":\"x\",\"state\":\"untriaged\"}", "bad_state" },
        { "{\"op\":\"add\",\"title\":\"x\",\"state\":\"false\",\"incident\":1}", "unknown_member" },
        { "{\"op\":\"add\",\"title\":\"x\",\"state\":\"false\",\"admin\":1}", "unknown_member" },
        { "{\"op\":\"close\",\"incident\":1,\"title\":\"x\"}", "unknown_member" },
        { "{\"op\":\"close\",\"incident\":1,\"ip\":\"10.0.0.1\"}", "unknown_member" },
        { "{\"op\":\"member\",\"incident\":1,\"note\":\"x\",\"remove\":1}", "unknown_member" },
        { "{\"op\":\"close\"}", "missing_incident" },
        { "{\"op\":\"close\",\"incident\":\"1\"}", "bad_incident" },
        { "{\"op\":\"close\",\"incident\":0}", "bad_incident" },
        { "{\"op\":\"drop\",\"incident\":1}", "bad_op" },
        { "{\"title\":\"x\"}", "missing_op" },
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        WT_EQ(post("/api/frrs/incident", BAD[i].body), 400);
        WT_HAS(body_of(g_out), BAD[i].why);
    }
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"close\",\"incident\":9}"), 404);
    WT_HAS(body_of(g_out), "no_such_incident");
    WT_EQ(store_int("SELECT COUNT(*) FROM incident"), 1);
    /* A cross-site POST is the gate's, as every write's. */
    web_req_t rq;
    base_rq(&rq, "/api/frrs/incident", "");
    rq.is_post = 1;
    snprintf(rq.origin, sizeof(rq.origin), "http://evil.example");
    rq.origin_count = 1;
    snprintf(rq.ctype, sizeof(rq.ctype), "application/json");
    rq.ctype_count = 1;
    rq.body = "{\"op\":\"close\",\"incident\":1}";
    rq.body_len = strlen(rq.body);
    rq.content_length = (long long)rq.body_len;
    WT_EQ(route(&rq), 403);
    WT_HAS(body_of(g_out), "bad_origin");
    WT_EQ(store_int("SELECT COUNT(*) FROM incident WHERE closes > 0"), 0);
    env_close();
}

/* Read-only: the routes answer, nothing is written. */
static void test_read_only(void) {
    env_open(0);
    if (!E.have_store) { env_close(); return; }
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"add\",\"title\":\"x\",\"state\":\"false\"}"), 405);
    WT_EQ(post("/api/frrs/triage/bulk", "{\"ids\":\"d1\",\"state\":\"false\"}"), 405);
    WT_EQ(get("/api/frrs/incidents", ""), 200);
    WT_HAS(body_of(g_out), "\"writes\":false");
    WT_EQ(store_int("SELECT COUNT(*) FROM incident"), 0);
    env_close();
}

/* Where no incident is involved, every triage answer is byte for byte
 * what it was before the incidents existed: an alert's /api/frrs/states
 * and /api/frrs/history, a POST /api/frrs/triage's answer shape, and
 * /api/alerts?triage=any filtered to a type no incident holds, read
 * before any incident and again after one holds two other alerts. Seen
 * red with tri_json() writing "incident":null when there is none (the
 * last POST's answer; the before and after reads then both carried it,
 * which is why that check is there). */
static void test_untouched_without_an_incident(void) {
    env_open(1);
    if (!E.have_store || !E.have_db) { env_close(); return; }
    char ids[24][32], ty[24][48];
    int n = alert_ids(ids, ty, 24);
    /* An alert whose type no other of the first three shares. */
    int x = -1;
    for (int i = 3; i < n && x < 0; i++)
        if (strcmp(ty[i], ty[0]) && strcmp(ty[i], ty[1]) && strcmp(ty[i], ty[2])) x = i;
    WT_ASSERT(x > 0);
    if (x <= 0) { env_close(); return; }
    char b[512], q[128], aq[160];
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"false\",\"note\":\"mine\"}", ids[x]);
    WT_EQ(post("/api/frrs/triage", b), 200);
    static char before[3][65536];
    snprintf(q, sizeof(q), "ids=%s,%s", ids[x], ids[2]);
    snprintf(aq, sizeof(aq), "limit=100&triage=any&type=%s", ty[x]);
    WT_EQ(get("/api/frrs/states", q), 200);
    snprintf(before[0], sizeof(before[0]), "%s", body_of(g_out));
    snprintf(q, sizeof(q), "id=%s", ids[x]);
    WT_EQ(get("/api/frrs/history", q), 200);
    snprintf(before[1], sizeof(before[1]), "%s", body_of(g_out));
    WT_EQ(get("/api/alerts", aq), 200);
    snprintf(before[2], sizeof(before[2]), "%s", body_of(g_out));
    WT_EQ(post("/api/frrs/incident", "{\"op\":\"add\",\"title\":\"x\",\"state\":\"noise\","
                                     "\"ip\":\"203.0.113.250\"}"), 200);
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"title\":\"y\",\"state\":\"known\",\"ids\":\"%s,%s\"}",
             ids[0], ids[1]);
    WT_EQ(post("/api/frrs/incident", b), 200);
    snprintf(q, sizeof(q), "ids=%s,%s", ids[x], ids[2]);
    WT_EQ(get("/api/frrs/states", q), 200);
    WT_EQ(strcmp(body_of(g_out), before[0]), 0);
    snprintf(q, sizeof(q), "id=%s", ids[x]);
    WT_EQ(get("/api/frrs/history", q), 200);
    WT_EQ(strcmp(body_of(g_out), before[1]), 0);
    WT_EQ(get("/api/alerts", aq), 200);
    WT_EQ(strcmp(body_of(g_out), before[2]), 0);
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\"}", ids[x]);
    WT_EQ(post("/api/frrs/triage", b), 200);
    WT_LACKS(body_of(g_out), "incident");
    env_close();
}

/* Nothing from the stream is stored: every TEXT column of the two
 * tables holds an id the alert routes give, a canonical address,
 * slothweb's own words or the POST body's text. The demo's stream
 * carries SSIDs and hostnames; none of them is in the file. */
static void test_nothing_from_the_stream_stored(void) {
    env_open(1);
    if (!E.have_store || !E.have_db) { env_close(); return; }
    char ids[16][32], ty[16][48];
    int n = alert_ids(ids, ty, 16);
    char b[1024];
    size_t o = (size_t)snprintf(b, sizeof(b), "{\"op\":\"add\",\"title\":\"t\",\"state\":\"noise\",\"ids\":\"");
    for (int i = 0; i < n; i++) o += (size_t)snprintf(b + o, sizeof(b) - o, "%s%s", i ? "," : "", ids[i]);
    snprintf(b + o, sizeof(b) - o, "\"}");
    WT_EQ(post("/api/frrs/incident", b), 200);
    WT_EQ(store_int("SELECT COUNT(*) FROM incident_member WHERE kind = 0"), n);
    WT_EQ(store_int("SELECT COUNT(*) FROM incident_member WHERE subject NOT GLOB '[sd][0-9A-Za-z]*'"), 0);
    WT_EQ(store_int("SELECT COUNT(*) FROM incident_member WHERE addr <> '' AND addr NOT GLOB"
                    " '[0-9a-f:.]*'"), 0);
    WT_EQ(store_int("SELECT COUNT(*) FROM incident_member WHERE who <> '' OR peer <> '127.0.0.1'"), 0);
    env_close();
}

#endif

/* ── the page ──────────────────────────────────────────────────────── */

void run_incident_tests(void) {
    WT_RUN(test_without_a_store);
#ifdef WITH_SQLITE
    WT_RUN(test_bulk_triage);
    WT_RUN(test_bulk_costs_one_token);
    WT_RUN(test_incident_by_ids);
    WT_RUN(test_precedence);
    WT_RUN(test_filter_auto_join);
    WT_RUN(test_agent_rules);
    WT_RUN(test_hostile_text);
    WT_RUN(test_read_only);
    WT_RUN(test_untouched_without_an_incident);
    WT_RUN(test_nothing_from_the_stream_stored);
#endif
}
