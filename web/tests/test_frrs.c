/* Triage and the FRRS record (web_frrs.h, docs/web-frrs-spec.md),
 * slothweb's first write surface: hand-built requests through the
 * router and over real loopback sockets, a sloth.db from the demo's
 * generator (sloth's own DDL, never a committed fixture), the stream
 * from the demo's own passes, and a store in a fresh directory.
 *
 * Every absence assertion here was seen red under the mutation its
 * comment names, applied in a copy of the tree, with the tree's sources
 * compared by sha256 afterwards, before the comment was written. The
 * migration's ROLLBACK made COMMIT turned test_store.c's v5 failure
 * red the same way. */
#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_assets.h"
#include "web_frrs.h"
#include "web_frrs_int.h"
#include "web_ingest.h"
#include "web_live.h"
#include "oui_csv.h"
#include "web_oui.h"
#include "web_metrics.h"
#include "web_rollup.h"
#include "web_routes.h"
#include "web_tsdb.h"
#include "web_server.h"
#include "wt_tmp.h"
#include "wtest.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

#define T SDB_NOW

int    demo_make_db(const char *path, long long now);
size_t demo_pass(long long t, long long start, unsigned long k, char *out, size_t cap);
const char *db_schema_sql(void);

static char g_out[262144];

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

/* One test's world: a store, the frrs module on it, the demo's sloth.db
 * and stream. Large: static. */
typedef struct {
    char           dir[TEST_TMP_MAX];
    char           store_path[TEST_TMP_MAX + 32];
    char           sdb_path[TEST_TMP_MAX + 32];
    web_store_t    store;
    int            have_store;
    web_frrs_t     f;
    web_live_t     live;
    web_slothdb_t  sdb;
    web_m4_t       m4;
    web_health_t   h;
} env_t;
static env_t E;

static void env_open(const char *assess, int writes) {
    memset(&E, 0, sizeof(E));
    snprintf(E.dir, sizeof(E.dir), "%s/slothweb-frrs-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(E.dir) != NULL);
    snprintf(E.store_path, sizeof(E.store_path), "%s/slothweb.db", E.dir);
    snprintf(E.sdb_path, sizeof(E.sdb_path), "%s/sloth.db", E.dir);
    char err[512];
    if (web_store_available()) {
        WT_EQ(web_store_open(&E.store, E.store_path, err, sizeof(err)), 0);
        E.have_store = 1;
    }
    WT_EQ(web_frrs_init(&E.f, E.have_store ? &E.store : NULL, assess, writes, err, sizeof(err)), 0);
    web_live_init(&E.live, "unix:/demo/sloth.sock");
    web_live_sock_connected(&E.live, 0);
    int have_db = web_store_available() && demo_make_db(E.sdb_path, T) == 0;
    web_sdb_fns_t fns = { NULL, NULL, NULL, &E.live };
    web_slothdb_init(&E.sdb, have_db ? E.sdb_path : "", &fns);
    E.m4.sdb = have_db ? &E.sdb : NULL;
    E.m4.frrs = &E.f;
    /* The demo's first twenty passes: the KARMA AP opens at the third,
     * the cleartext credential at the fourth; every ledger record type
     * is in each. */
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
    return r.status;
}

/* A POST as the server hands it to the router: the headers it keeps,
 * the body read, the peer. origin or ctype NULL: the header absent. */
static int post_h(const char *path, const char *query, const char *body, const char *origin,
                  const char *ctype, const char *peer) {
    web_req_t rq;
    web_resp_t r;
    base_rq(&rq, path, query);
    rq.is_post = 1;
    if (origin) { snprintf(rq.origin, sizeof(rq.origin), "%s", origin); rq.origin_count = 1; }
    if (ctype) { snprintf(rq.ctype, sizeof(rq.ctype), "%s", ctype); rq.ctype_count = 1; }
    rq.body = body;
    rq.body_len = strlen(body);
    rq.content_length = (long long)rq.body_len;
    /* Two seconds apart, one token's refill: the bucket is its own test. */
    E.h.now_ms += 2000;
    snprintf(rq.peer, sizeof(rq.peer), "%s", peer ? peer : "127.0.0.1");
    memset(&r, 0, sizeof(r));
    if (web_route(&rq, &E.h, 1, g_out, sizeof(g_out), &r) != 0) return -1;
    g_out[r.out_len < sizeof(g_out) ? r.out_len : sizeof(g_out) - 1] = '\0';
    return r.status;
}

static int post(const char *path, const char *body) {
    return post_h(path, "", body, "http://127.0.0.1:8770", "application/json", NULL);
}

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

static long long json_int(const char *b, const char *key) {
    char k[64];
    snprintf(k, sizeof(k), "\"%s\":", key);
    const char *p = strstr(b, k);
    return p ? atoll(p + strlen(k)) : -1;
}

/* The answer's own "count", after its rows. */
static long long rows_count(const char *b) {
    const char *p = strstr(b, "],\"count\":");
    return p ? atoll(p + 10) : -1;
}

static int count_of(const char *s, const char *w) {
    int n = 0;
    for (const char *q = strstr(s, w); q; q = strstr(q + 1, w)) n++;
    return n;
}

#ifdef WITH_SQLITE
/* A needle in a file's bytes (the store, and its WAL). */
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

#endif

/* ── triage ─────────────────────────────────────────────────────────── */

/* A decision, its history, the clear that undoes it (a second row, not
 * a delete), and a note holding markup kept as typed and served
 * escaped. The escape seen red with web_jw_str(w, t->note) made
 * web_jw_raw(w, t->note) in tri_json() (the <b> then reached the body). */
static void test_triage_round_trip(void) {
    env_open(NULL, 1);
    char id[40];
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    char b[512];
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\",\"note\":\"the <b>scanner</b>\","
             "\"by\":\"op\"}", id);
    WT_EQ(post("/api/frrs/triage", b), E.have_store ? 200 : 503);
    if (!E.have_store) { WT_HAS(g_out, "no_store"); env_close(); return; }
    WT_HAS(g_out, "\"state\":\"noise\"");
    WT_HAS(g_out, "the \\u003cb\\u003escanner\\u003c/b\\u003e");
    WT_LACKS(body_of(g_out), "<b>");
    WT_HAS(g_out, "\"peer\":\"127.0.0.1\"");
    WT_HAS(g_out, "\"by\":\"op\"");
    char q[96];
    snprintf(q, sizeof(q), "ids=%s", id);
    WT_EQ(get("/api/frrs/states", q), 200);
    WT_HAS(g_out, "\"state\":\"noise\"");
    WT_HAS(g_out, "\"types\":{");
    WT_HAS(g_out, "\"PORT_SCAN\"");
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"untriaged\"}", id);
    WT_EQ(post("/api/frrs/triage", b), 200);
    WT_HAS(g_out, "\"prev_state\":\"noise\"");
    snprintf(q, sizeof(q), "id=%s", id);
    WT_EQ(get("/api/frrs/history", q), 200);
    WT_EQ(count_of(body_of(g_out), "\"prev_state\":"), 3);   /* current + two rows */
    WT_HAS(g_out, "\"current\":{\"state\":\"untriaged\"");
#ifdef WITH_SQLITE
    WT_ASSERT(store_has("the <b>scanner</b>"));      /* stored as typed */
#endif
    env_close();
}

/* triage= on /api/alerts dims, never drops: the open rows with
 * triage=any are exactly the open rows without it, and the counts sum
 * to them. Seen red with web_frrs_filter_pass() answering
 * state == WEB_TRI_UNTRIAGED for WEB_TRI_F_ANY (the noise row gone). */
static void test_triaged_out_is_counted_not_dropped(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    char id[40], b[256];
    WT_ASSERT(id_of("KARMA_AP", id, sizeof(id)));
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"false\"}", id);
    WT_EQ(post("/api/frrs/triage", b), 200);
    WT_EQ(get("/api/alerts", "state=open&limit=100"), 200);
    long long plain = rows_count(body_of(g_out));
    WT_ASSERT(plain >= 2);
    WT_LACKS(body_of(g_out), "\"triage\"");          /* without it, as before */
    WT_EQ(get("/api/alerts", "state=open&limit=100&triage=any"), 200);
    WT_EQ(rows_count(body_of(g_out)), plain);
    WT_EQ(count_of(body_of(g_out), "\"triage\":{\"state\":"), plain);
    WT_EQ(json_int(body_of(g_out), "false") + json_int(body_of(g_out), "untriaged") +
          json_int(body_of(g_out), "noise") + json_int(body_of(g_out), "incident"), plain);
    WT_EQ(get("/api/alerts", "state=open&limit=100&triage=out"), 200);
    WT_EQ(rows_count(body_of(g_out)), 1);
    WT_EQ(get("/api/alerts", "state=open&limit=100&triage=untriaged"), 200);
    WT_EQ(rows_count(body_of(g_out)), plain - 1);
    WT_EQ(get("/api/alerts", "triage=maybe"), 400);
    WT_HAS(g_out, "bad_triage");
    /* The tile's figures: the open count, and the triaged out within it. */
    WT_EQ(get("/api/frrs/summary", ""), 200);
    WT_EQ(json_int(body_of(g_out), "total"), plain);
    WT_EQ(json_int(body_of(g_out), "out"), 1);
    WT_ASSERT(json_int(body_of(g_out), "out") <= json_int(body_of(g_out), "total"));
    env_close();
}

/* ── the write path's refusals ──────────────────────────────────────── */

/* Cross-site writes. Each refusal leaves the store without a row.
 * Seen red: the Origin/Host equality in web_frrs_origin_ok() replaced by
 * `return 1` (evil.example accepted); the `rq->origin_count != 1 ||`
 * test removed (the doubled Origin accepted). The missing Origin is
 * refused by two guards (the count and the scheme), so no one mutation
 * isolates it: it is asserted, not claimed as covered alone. */
static void test_cross_origin_refused(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    char id[40], b[256];
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\"}", id);
    static const char *const bad[] = {
        "http://evil.example", "http://127.0.0.1:8771", "https://127.0.0.1:8770", "null",
        "http://127.0.0.1:8770/", "http://user@127.0.0.1:8770",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        WT_EQ(post_h("/api/frrs/triage", "", b, bad[i], "application/json", NULL), 403);
        WT_HAS(g_out, "bad_origin");
    }
    WT_EQ(post_h("/api/frrs/triage", "", b, NULL, "application/json", NULL), 403);
    /* Two Origin lines, the first this page's: refused whole. */
    {
        web_req_t rq;
        web_resp_t r;
        base_rq(&rq, "/api/frrs/triage", "");
        rq.is_post = 1;
        snprintf(rq.origin, sizeof(rq.origin), "http://127.0.0.1:8770");
        rq.origin_count = 2;
        snprintf(rq.ctype, sizeof(rq.ctype), "application/json");
        rq.ctype_count = 1;
        rq.body = b;
        rq.body_len = strlen(b);
        snprintf(rq.peer, sizeof(rq.peer), "127.0.0.1");
        WT_EQ(web_route(&rq, &E.h, 1, g_out, sizeof(g_out), &r), 0);
        WT_EQ(r.status, 403);
    }
    /* Sec-Fetch-Site from another site. */
    {
        web_req_t rq;
        web_resp_t r;
        base_rq(&rq, "/api/frrs/triage", "");
        rq.is_post = 1;
        snprintf(rq.origin, sizeof(rq.origin), "http://127.0.0.1:8770");
        rq.origin_count = 1;
        snprintf(rq.ctype, sizeof(rq.ctype), "application/json");
        rq.ctype_count = 1;
        snprintf(rq.fetch_site, sizeof(rq.fetch_site), "cross-site");
        rq.body = b;
        rq.body_len = strlen(b);
        WT_EQ(web_route(&rq, &E.h, 1, g_out, sizeof(g_out), &r), 0);
        WT_EQ(r.status, 403);
    }
    WT_EQ(get("/api/frrs/summary", ""), 200);
    WT_EQ(json_int(body_of(g_out), "rows"), 0);
    /* The port defaulted on both sides is the same origin. */
    WT_EQ(post_h("/api/frrs/triage", "", b, "http://127.0.0.1:8770", "application/json; charset=utf-8",
                 NULL), 200);
    env_close();
}

/* Content-Type, unknown members, bounds, control bytes. Seen red: the
 * Content-Type check in web_frrs_gate() removed (text/plain written);
 * frrs_members_ok() returning 1 (the "admin" member accepted); the bound
 * in frrs_text() made `f->slen > max + 1` (a 241-byte note stored). */
static void test_body_rules(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    char id[40], b[1024], note[300];
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\"}", id);
    WT_EQ(post_h("/api/frrs/triage", "", b, "http://127.0.0.1:8770", "text/plain", NULL), 415);
    WT_HAS(g_out, "bad_content_type");
    WT_EQ(post_h("/api/frrs/triage", "", b, "http://127.0.0.1:8770", "application/jsonx", NULL), 415);
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\",\"admin\":true}", id);
    WT_EQ(post("/api/frrs/triage", b), 400);
    WT_HAS(g_out, "unknown_member");
    WT_EQ(post("/api/frrs/triage", "[1,2]"), 400);
    WT_EQ(post("/api/frrs/triage", "{\"id\":"), 400);
    WT_HAS(g_out, "bad_body");
    memset(note, 'n', 241);
    note[241] = '\0';
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\",\"note\":\"%s\"}", id, note);
    WT_EQ(post("/api/frrs/triage", b), 400);
    WT_HAS(g_out, "too_long");
    WT_EQ(get("/api/frrs/summary", ""), 200);
    WT_EQ(json_int(body_of(g_out), "rows"), 0);
    note[240] = '\0';
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\",\"note\":\"%s\"}", id, note);
    WT_EQ(post("/api/frrs/triage", b), 200);
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"false\",\"by\":\"a\\u0007b\"}", id);
    WT_EQ(post("/api/frrs/triage", b), 400);
    WT_HAS(g_out, "bad_text");
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"maybe\"}", id);
    WT_EQ(post("/api/frrs/triage", b), 400);
    WT_HAS(g_out, "bad_state");
    WT_EQ(post("/api/frrs/triage", "{\"id\":\"d999999\",\"state\":\"noise\"}"), 404);
    WT_EQ(post("/api/frrs/triage", "{\"id\":\"x1\",\"state\":\"noise\"}"), 404);
    env_close();
}

/* A GET can never write: a write path answers POST only, a read path
 * GET only. Seen red with the `post != rq->is_post` check removed from
 * web_frrs_route() (the GET then a 404, not the 405). */
static void test_get_cannot_write(void) {
    env_open(NULL, 1);
    char id[40], q[128];
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    snprintf(q, sizeof(q), "id=%s&state=noise", id);
    WT_EQ(get("/api/frrs/triage", q), 405);
    WT_HAS(g_out, "Allow: POST\r\n");
    WT_EQ(get("/api/frrs/tacdb/unit", "op=create&name=x"), 405);
    WT_EQ(post("/api/frrs/states", "{}"), 405);
    WT_HAS(g_out, "Allow: GET, HEAD\r\n");
    WT_EQ(get("/api/frrs/summary", ""), 200);
    if (E.have_store) WT_EQ(json_int(body_of(g_out), "rows"), 0);
    else WT_HAS(g_out, "\"rows\":null");
    env_close();
}

/* The token bucket: ten at once, the eleventh refused, one more every
 * two seconds, peers apart. Seen red with the bucket refilled to the
 * burst on every call (the eleventh admitted). */
static void test_rate_limit(void) {
    static web_frrs_t f;
    char err[256];
    WT_EQ(web_frrs_init(&f, NULL, NULL, 1, err, sizeof(err)), 0);
    for (int i = 0; i < 10; i++) WT_EQ(web_frrs_rate_admit(&f, "192.0.2.1", 1000, 1), 1);
    WT_EQ(web_frrs_rate_admit(&f, "192.0.2.1", 1000, 1), 0);
    WT_EQ(web_frrs_rate_admit(&f, "192.0.2.2", 1000, 1), 1);
    WT_EQ(web_frrs_rate_admit(&f, "192.0.2.1", 2900, 1), 0);
    WT_EQ(web_frrs_rate_admit(&f, "192.0.2.1", 3000, 1), 1);
    WT_EQ(web_frrs_rate_admit(&f, "192.0.2.1", 3000, 1), 0);
    /* The import costs five. */
    WT_EQ(web_frrs_rate_admit(&f, "192.0.2.3", 0, 5), 1);
    WT_EQ(web_frrs_rate_admit(&f, "192.0.2.3", 0, 5), 1);
    WT_EQ(web_frrs_rate_admit(&f, "192.0.2.3", 0, 5), 0);
    web_frrs_destroy(&f);
}

/* ── what is stored ─────────────────────────────────────────────────── */

#ifdef WITH_SQLITE
/* A cleartext credential's key names a username: triaging it stores
 * none of it, and no answer carries it. And a stream string (a beacon's
 * SSID, sent here as an injection attempt) reaches no table: the ledger
 * is memory. Seen red: the alert key's text stored as the descriptor's
 * addr in resolve_id() (the username in the file and in /history; a
 * desc_addr() taking the key first did not reach the row, as sloth.db's
 * match_ip replaces it); the ledger
 * BSSID's SSID copied into the platform's vendor in post_platform()
 * (the SSID in the file). */
static void test_no_credential_and_no_stream_string_stored(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    char id[40], b[512], q[96];
    WT_ASSERT(id_of("CLEARTEXT_CRED", id, sizeof(id)));
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"incident\"}", id);
    WT_EQ(post("/api/frrs/triage", b), 200);
    WT_LACKS(g_out, "demo-user");
    snprintf(q, sizeof(q), "id=%s", id);
    WT_EQ(get("/api/frrs/history", q), 200);
    WT_LACKS(g_out, "demo-user");
    WT_HAS(g_out, "\"addr\":\"192.0.2.16\"");
    snprintf(q, sizeof(q), "ids=%s", id);
    WT_EQ(get("/api/frrs/states", q), 200);
    WT_LACKS(g_out, "demo-user");
    /* A hostile SSID on the air, then the TACDB filing that BSSID. */
    web_jrec_t *r = malloc(sizeof(*r));
    static const char L[] = "{\"type\":\"beacon\",\"ts\":1792627000,\"bssid\":\"02:de:00:00:00:c1\","
                            "\"ssid\":\"' OR 1=1--\",\"channel\":6,\"enc\":\"OPEN\"}";
    WT_ASSERT(r && web_jl_parse(L, sizeof(L) - 1, r) == WEB_JL_OK);
    if (r) web_frrs_record(&E.f, r);
    free(r);
    WT_EQ(get("/api/frrs/report", "kind=bssid&addr=02:de:00:00:00:c1"), 200);
    WT_HAS(g_out, "OR 1=1--");                       /* shown, from memory */
    WT_EQ(post("/api/frrs/tacdb/platform", "{\"op\":\"create\",\"nomenclature\":\"cafe ap\","
               "\"class\":\"ap\",\"emitter_kind\":\"bssid\",\"emitter_addr\":\"02:de:00:00:00:c1\"}"), 200);
    WT_EQ(get("/api/frrs/suggest", ""), 200);
    const char *tok = strstr(body_of(g_out), "\"token\":\"");
    WT_ASSERT(tok != NULL);
    if (tok) {
        char t[64];
        const char *e = strchr(tok + 9, '"');
        snprintf(t, sizeof(t), "%.*s", e ? (int)(e - tok - 9) : 0, tok + 9);
        snprintf(b, sizeof(b), "{\"op\":\"confirm\",\"suggest\":\"%s\"}", t);
        WT_EQ(post("/api/frrs/tacdb/platform", b), 200);
    }
    WT_EQ(get("/api/frrs/export", ""), 200);
    WT_LACKS(g_out, "demo-user");
    WT_LACKS(g_out, "OR 1=1");
    web_frrs_destroy(&E.f);
    web_store_close(&E.store);
    WT_ASSERT(!store_has("demo-user"));
    WT_ASSERT(!store_has("00c0ffee"));
    WT_ASSERT(!store_has("OR 1=1"));
    WT_ASSERT(store_has("cafe ap"));                  /* the scan reads the file */
    memset(&E.f, 0, sizeof(E.f));
    memset(&E.store, 0, sizeof(E.store));
    web_slothdb_destroy(&E.sdb);
    web_live_destroy(&E.live);
    test_rm_tree(E.dir);
}

/* A row filed before sloth.db held its finding gets the finding once,
 * from NULL, never a second time. Seen red with `finding IS NULL AND`
 * taken out of tri_write()'s UPDATE (the earlier row's 4242 rewritten). */
static void test_finding_set_once(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    char id[40], b[256];
    WT_ASSERT(id_of("KARMA_AP", id, sizeof(id)));
    WT_ASSERT(id[0] == 's');
    /* An earlier row under the same stream handle, already resolved to
     * another rowid (a sloth.db rebuilt since). */
    char sql[512];
    snprintf(sql, sizeof(sql), "INSERT INTO triage (subject, finding, type, state, ts) VALUES"
             " ('%s', 4242, 20, 2, 1)", id);
    WT_EQ(sdb_exec(E.store_path, sql), 0);
    /* And one not yet resolved. */
    snprintf(sql, sizeof(sql), "INSERT INTO triage (subject, finding, type, state, ts) VALUES"
             " ('%s', NULL, 20, 1, 2)", id);
    WT_EQ(sdb_exec(E.store_path, sql), 0);
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"incident\"}", id);
    WT_EQ(post("/api/frrs/triage", b), 200);
    const char *d = strstr(body_of(g_out), "\"finding\":\"d");
    WT_ASSERT(d != NULL);
    long long rid = d ? atoll(d + 12) : 0;
    WT_ASSERT(rid > 0 && rid != 4242);
    /* Read the rows back through a GET of the history. */
    char q[96];
    snprintf(q, sizeof(q), "id=%s", id);
    WT_EQ(get("/api/frrs/history", q), 200);
    WT_EQ(count_of(body_of(g_out), "{\"state\":"), 4);   /* current + three rows */
    web_frrs_destroy(&E.f);
    web_store_close(&E.store);
    memset(&E.f, 0, sizeof(E.f));
    memset(&E.store, 0, sizeof(E.store));
    char err[512];
    WT_EQ(web_store_open(&E.store, E.store_path, err, sizeof(err)), 0);
    WT_EQ(web_frrs_init(&E.f, &E.store, NULL, 1, err, sizeof(err)), 0);
    snprintf(q, sizeof(q), "id=d%lld", rid);
    WT_EQ(get("/api/frrs/history", q), 200);
    /* By the finding: the resolved rows, not the one still on 4242. */
    WT_EQ(count_of(body_of(g_out), "{\"state\":"), 3);
    snprintf(q, sizeof(q), "id=d4242");
    WT_EQ(get("/api/frrs/history", q), 404);
    env_close();
}

#endif

/* ── the recommendation ─────────────────────────────────────────────── */

static void write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    WT_ASSERT(f != NULL);
    if (!f) return;
    fputs(text, f);
    fclose(f);
}

/* docs/wiki/alert-assessments/KARMA_AP.md (b1fbc2a), its three verdict lines verbatim */
static const char FM_KARMA_AP[] =
    "---\n"
    "severity_assessment: agree - WARN for a bare SSID-count candidate, CRIT only when somethin"
    "g ties the pattern to this radio (a single station's PNL asks for >=2 of its SSIDs, a shar"
    "ed-victim deauth-then-lure chain, or a capture-verified tool match). The #90 pass that int"
    "roduced this split is the right call\n"
    "false_positive_risk: medium - KARMA_SSID_THRESH is 3 while legitimate multi-VAP gear sits "
    "at 1-4 SSIDs, so lawful 3-4-SSID APs, repeaters/mesh nodes, and SSID-cycling captive-porta"
    "l gear all cross the candidate bar; CRIT corroboration is what keeps those at WARN\n"
    "noise_verdict: noisy on the reference host - 60 keys, 415,695,109 fires, max_sev 1. 415.7e"
    "6 / 60 = 6.93e6 evaluations per BSSID; at 4 or more ticks/s that is at most ~20 days of he"
    "ld candidate state per BSSID (an upper bound: 250 ms is the longest wait between ticks), s"
    "o the count is time-in-table, not lure activity. max_sev 1 (WARN) means none of the 60 wer"
    "e corroborated to CRIT - they are candidates, most of them benign multi-SSID radios. Recom"
    "mend: show observations/first_seen/last_seen and the WARN-vs-CRIT split on the alert page,"
    " never count; the rule is already well-gated, so the fix is presentational plus raising --"
    "tune karma.ssid_thresh in a multi-VAP-dense site\n"
    "---\n";
/* docs/wiki/alert-assessments/ARP_SPOOF.md (b1fbc2a), its three verdict lines verbatim */
static const char FM_ARP_SPOOF[] =
    "---\n"
    "severity_assessment: too high as a blanket - CRIT is warranted when the contested IP is th"
    "e sensor's default gateway or resolver; a DHCP lease moved to a new machine, a VRRP/HSRP f"
    "ailover, or a dual-homed host produces the identical observation and is not an attack\n"
    "false_positive_risk: high - \"one IP, two MACs over time\" is also what lease reassignment"
    ", first-hop redundancy and a laptop moving wired-to-wireless produce by design\n"
    "noise_verdict: not seen on the reference host - host is null; because the input is the sen"
    "sor host's own neighbour cache, a quiet result means no binding the kernel held changed, n"
    "ot that no cache poisoning occurred elsewhere on the segment\n"
    "---\n";
/* docs/wiki/alert-assessments/PORT_SCAN.md (b1fbc2a), its three verdict lines verbatim */
static const char FM_PORT_SCAN[] =
    "---\n"
    "severity_assessment: agree - LOW is right for reconnaissance that reaches only this host's"
    " own listening ports; the rule cannot see anything worse than \"touched N services\"\n"
    "false_positive_risk: medium - a legitimate client that opens many services on this host (a"
    " browser against a local web stack, a monitoring/vuln scanner, a CDN-less mesh peer) count"
    "s the same as nmap; but the private-source exclusion removes most LAN noise\n"
    "noise_verdict: not seen on the reference host - host:null. Expected: the rule only counts "
    "*public* (non-RFC1918, non-CGNAT, IPv4) sources connecting to this host's *own* listening "
    "TCP ports, so a NAT'd host with no exposed services can never fire it; the silence is a bl"
    "ind spot, not cleanliness\n"
    "---\n";
/* docs/wiki/alert-assessments/PM_FORGE.md (b1fbc2a): its whole front matter, verbatim, 4,823 bytes */
static const char FM_PM_FORGE[] =
    "---\n"
    "type: PM_FORGE\n"
    "technique: T1557\n"
    "rule_file: src/alerts/rules_wifi_mgmt.c:1098 of rule_pm_forge()\n"
    "count_semantics: per poll tick while a station's pm_forge_t row has contradiction_count > "
    "0. fire_ev() at rules_wifi_mgmt.c:1124 runs on every alerts_update() pass (src/poll.c:296;"
    " one per poll tick: POLL_MS = 250 ms default, include/sloth.h:28, overridable with --refre"
    "sh-ms, and the loop also wakes early on an escalation (main.c:1628-1671, src/event_wake.h)"
    ") for every row in the 128-entry LRU table (MAX_PM_FORGE_ENTRIES, src/pm_forge.h:36) whose"
    " lifetime contradiction_count is non-zero. The counter is cleared only by table eviction ("
    "pm_forge.c:15-31); the rule has NO recency bound (contrast rule_queue_evict at rules_wifi_"
    "mgmt.c:1189-1191). count = ticks of residence, not contradictions; the \"%d time(s)\" fiel"
    "d in the detail is the number of contradicting PM=0 data frames, not of distinct pairs: on"
    "e PM=1 Null is never cleared after it is matched, so it can be counted against every paylo"
    "ad frame on another TID inside the beacon interval, and up to 8 evidence-ring frame IDs (4"
    " pairs) are cited.\n"
    "severity_assessment: too high as escalated, agree as default - WARN for an observed PM=1/P"
    "M=0 inconsistency is right (sloth cannot say which side is spoofed); escalating to CRIT pu"
    "rely because the BSSID is --my-bssid is questionable, because the operator's own network i"
    "s where benign fast wake-ups are most common, and max_sev=2 on the reference host shows th"
    "at CRIT path is being taken. That the stations involved were ordinary clients is the likel"
    "y reading, but the count does not establish it.\n"
    "false_positive_risk: high - the rule treats \"PM=0 data on a different TID within one beac"
    "on interval after a PM=1 Null\" as impossible for one radio, but 802.11 lets a station lea"
    "ve power-save at any time with any frame; a client that announces sleep and is woken ~50-1"
    "00 ms later by new uplink traffic on another access category produces exactly this pair. T"
    "here is no minimum count, no rate, and no check that the two frames are inconsistent in se"
    "quence number or RSSI.\n"
    "noise_verdict: very noisy on the reference host - 141,288,757 fires on 23 keys, max_sev CR"
    "IT. ~6.14 M evaluations per key; ticks run at 4/s or more (250 ms is the longest wait), so"
    " that is at most 17.8 days of continuous re-firing per station, consistent with 23 station"
    "s each tripping once (or a few times) and then being reported every tick for as long as th"
    "eir rows stayed in the table; the figure does not establish how long the run was. The CRIT"
    " means at least one station was on an operator-designated BSSID (--my-bssid), i.e. most li"
    "kely a client of the owner's own AP, the benign-wake case. Note that `mine` tests the stat"
    "ion's most recently seen BSSID (pm_forge.c:71), not the BSSID of the contradicting frames."
    " Recommend: (1) a recency bound (new knob pmforge.report_secs, mirroring queue_evict.repor"
    "t_secs) so a row stops firing once last_contradiction_ts ages out - the only one of these "
    "that reduces the count; (2) a minimum contradiction count or rate before any fire (cuts fa"
    "lse positives, but does nothing to the count if the 23 stations already exceed it); (3) re"
    "quire QUEUE_EVICT corroboration (the issue's own A+B rule) for CRIT rather than ownership "
    "alone (a severity fix: it changes only the severity passed to fire_ev, rules_wifi_mgmt.c:1"
    "124, and removes no evaluations); (4) compare sequence numbers / RSSI of the two frames, s"
    "ince a forged Null from a second radio does not sit in the victim's sequence space.\n"
    "prevalence: the design flaw is real and standard-level (CVE-2022-47522 [5], \"Framing Fram"
    "es\", USENIX Security 2023 [6]; FreeBSD, Cisco, SonicWall advisories [8][9][5]), but Cisco"
    " characterises it as \"an opportunistic attack\" whose gain \"would be of minimal value in"
    " a securely configured network\" [8], and from Linux 5.6 the kernel drops data frames when"
    " no key is available, which the paper says prevents its plaintext-after-key-removal method"
    " on Linux APs (\302\2473.5.1). The other leak paths it demonstrates (group-key and all-zero-key e"
    "ncryption on other stacks) are not covered by that fix [6]. No in-the-wild exploitation re"
    "port was located in this pass. Public PoC exists for the FreeBSD queue-leak and SA-Query v"
    "ariants [7]; MacStealer covers the separate client-isolation variant, not power-save [10]."
    "\n"
    "tuning: [--my-bssid (WARN->CRIT escalation, rules_wifi_mgmt.c:1108,1124); --collect-handsh"
    "akes + --eapol-dir with pcap.min_severity (default 2 = CRIT only) and pcap.key_cooldown_se"
    "cs (3600) write the cited evidence frames as <incident>-<event>-PM_FORGE.pcap; --pcap-dir "
    "alone does NOT apply (match_ip NULL, \"L2 only\"); QUEUE_EVICT reads this table within QUE"
    "UE_EVICT_CORROB_SECS (10 s) but does not change PM_FORGE; --iface <monitor radio>, --hop; "
    "no pmforge.* knob exists today]\n"
    "researched: 2026-10-27\n"
    "---\n";

/* The front matter as the assessment batch writes it (its own lines,
 * above, not one-word stand-ins): noise is recommended only where
 * false_positive_risk begins "high" AND noise_verdict "noisy" / "very
 * noisy"; nothing recommends false or incident; an assessment below the
 * bar says "no automatic triage" (why_none), no file "no assessment".
 * The file is found by the type's own name; no front matter, or no
 * directory, no recommendation.
 *
 * KARMA_AP (medium, noisy) recommending nothing was seen red with the
 * fpr test dropped from web_frrs_recommend() (`if (fm_starts(fm->fpr,
 * "high") &&` deleted, the noise_verdict alone deciding, as first
 * built): "state":"noise". ARP_SPOOF's "false_positive_risk: high"
 * recommending nothing was seen red with `if (fm_starts(fm->fpr,
 * "high")) return WEB_TRI_FALSE;` added before the noise test (the
 * state became "false"); PORT_SCAN's "severity_assessment: agree"
 * recommending nothing was seen red with the same line for fm->sev and
 * "agree" returning WEB_TRI_INCIDENT. PM_FORGE's front matter (4,823
 * bytes) found was seen red with WEB_FRRS_ASSESS_MAX back at 4096
 * ("front_matter":null). */
static void test_follow_recommended(void) {
    char dir[TEST_TMP_MAX + 16];
    snprintf(dir, sizeof(dir), "%s/frrs-assess-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(dir) != NULL);
    char p[TEST_TMP_MAX + 64];
    static const struct { const char *type, *text; } F[] = {
        { "KARMA_AP", FM_KARMA_AP }, { "ARP_SPOOF", FM_ARP_SPOOF }, { "PORT_SCAN", FM_PORT_SCAN },
        { "PM_FORGE", FM_PM_FORGE },
    };
    static char doc[16384];
    for (size_t i = 0; i < sizeof(F) / sizeof(F[0]); i++) {
        snprintf(p, sizeof(p), "%s/%s.md", dir, F[i].type);
        /* Each with a body below its front matter, as the files have,
         * holding verdict lines the reader must not take. */
        snprintf(doc, sizeof(doc), "%s## What the rule checks\nfalse_positive_risk: high\n"
                 "noise_verdict: noisy\n", F[i].text);
        write_file(p, doc);
    }
    WT_EQ(strlen(FM_PM_FORGE), 4823);                 /* past the old 4096 */
    snprintf(p, sizeof(p), "%s/SMB1_USE.md", dir);
    write_file(p, "no front matter\nfalse_positive_risk: high\nnoise_verdict: noisy\n");
    env_open(dir, 1);
    WT_EQ(get("/api/frrs/recommend", "type=KARMA_AP"), 200);
    WT_HAS(g_out, "\"state\":null");
    WT_HAS(g_out, "\"why_none\":\"no_automatic_triage\"");
    WT_HAS(g_out, "\"noise_verdict\":\"noisy on the reference host");     /* shown, as advice */
    WT_EQ(get("/api/frrs/recommend", "type=ARP_SPOOF"), 200);
    WT_HAS(g_out, "\"state\":null");
    WT_HAS(g_out, "\"false_positive_risk\":\"high - ");          /* shown, as advice */
    WT_LACKS(g_out, "\"state\":\"false\"");
    WT_EQ(get("/api/frrs/recommend", "type=PORT_SCAN"), 200);
    WT_HAS(g_out, "\"state\":null");
    WT_HAS(g_out, "\"severity_assessment\":\"agree - ");
    WT_LACKS(g_out, "\"state\":\"incident\"");
    WT_EQ(get("/api/frrs/recommend", "type=PM_FORGE"), 200);
    WT_LACKS(g_out, "\"front_matter\":null");
    WT_HAS(g_out, "\"false_positive_risk\":\"high - the rule treats");
    WT_HAS(g_out, "\"state\":\"noise\"");
    WT_HAS(g_out, "\"basis\":\"false_positive_risk high; noise_verdict: very noisy on the reference");
    WT_HAS(g_out, "\"why_none\":null");
    WT_EQ(get("/api/frrs/recommend", "type=SMB1_USE"), 200);
    WT_HAS(g_out, "\"state\":null");
    WT_HAS(g_out, "\"front_matter\":null");
    WT_HAS(g_out, "\"why_none\":\"no_assessment\"");
    WT_EQ(get("/api/frrs/recommend", "type=../../etc/passwd"), 400);
    if (E.have_store) {
        char id[40], b[256];
        WT_ASSERT(id_of("KARMA_AP", id, sizeof(id)));
        snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"recommended\"}", id);
        WT_EQ(post("/api/frrs/triage", b), 409);
        WT_HAS(g_out, "no_recommendation");
        WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
        snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"recommended\"}", id);
        WT_EQ(post("/api/frrs/triage", b), 409);
        WT_HAS(g_out, "no_recommendation");
    }
    env_close();
    /* The POST path where the bar is met: a synthetic KARMA_AP file
     * (the demo has no alert of a type whose real assessment meets it). */
    snprintf(p, sizeof(p), "%s/KARMA_AP.md", dir);
    write_file(p, "---\nfalse_positive_risk: high - synthetic, for this test\n"
                  "noise_verdict: noisy - synthetic, for this test\n---\n");
    env_open(dir, 1);
    if (E.have_store) {
        char id[40], b[256];
        WT_ASSERT(id_of("KARMA_AP", id, sizeof(id)));
        snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"recommended\"}", id);
        WT_EQ(post("/api/frrs/triage", b), 200);
        WT_HAS(g_out, "\"via\":\"recommended\"");
        WT_HAS(g_out, "\"state\":\"noise\"");
        WT_HAS(g_out, "\"basis\":\"false_positive_risk high; noise_verdict: noisy - synthetic");
    }
    env_close();
    test_rm_tree(dir);
    env_open(NULL, 1);
    WT_EQ(get("/api/frrs/recommend", "type=KARMA_AP"), 200);
    WT_HAS(g_out, "\"source\":\"none\"");
    WT_HAS(g_out, "\"state\":null");
    env_close();
    /* A directory that is not there is none: no recommendation yet. */
    env_open("/nonexistent/sloth-assessments", 1);
    WT_EQ(get("/api/frrs/recommend", "type=PM_FORGE"), 200);
    WT_HAS(g_out, "\"source\":\"none\"");
    env_close();
}

/* The shipped assessments themselves, by name: FRAG_PLAINTEXT ("very
 * noisy", false_positive_risk "low") and SMB1_USE ("noisy in count,
 * quiet in findings", "low") are real findings re-counted, and get no
 * noise; PM_FORGE and WPA_DOWNGRADE (both "high" and "very noisy") do.
 * Read from docs/wiki/alert-assessments, the files make install ships.
 * FRAG_PLAINTEXT's and SMB1_USE's seen red with the fpr test dropped
 * (the mutation above): both "state":"noise". */
static void test_recommend_from_the_shipped_assessments(void) {
    env_open("docs/wiki/alert-assessments", 1);
    static const char *const NONE[] = { "FRAG_PLAINTEXT", "SMB1_USE" };
    for (size_t i = 0; i < sizeof(NONE) / sizeof(NONE[0]); i++) {
        char q[64];
        snprintf(q, sizeof(q), "type=%s", NONE[i]);
        WT_EQ(get("/api/frrs/recommend", q), 200);
        WT_HAS(g_out, "\"source\":\"dir\"");
        WT_HAS(g_out, "\"false_positive_risk\":\"low - ");
        WT_HAS(g_out, "\"state\":null");
        WT_HAS(g_out, "\"why_none\":\"no_automatic_triage\"");
        WT_LACKS(g_out, "\"state\":\"noise\"");
    }
    WT_EQ(get("/api/frrs/recommend", "type=FRAG_PLAINTEXT"), 200);
    WT_HAS(g_out, "\"noise_verdict\":\"very noisy");
    WT_EQ(get("/api/frrs/recommend", "type=SMB1_USE"), 200);
    WT_HAS(g_out, "\"noise_verdict\":\"noisy in count");
    static const char *const NOISE[] = { "PM_FORGE", "WPA_DOWNGRADE" };
    for (size_t i = 0; i < sizeof(NOISE) / sizeof(NOISE[0]); i++) {
        char q[64];
        snprintf(q, sizeof(q), "type=%s", NOISE[i]);
        WT_EQ(get("/api/frrs/recommend", q), 200);
        WT_HAS(g_out, "\"state\":\"noise\"");
    }
    env_close();
}

/* ── the record ─────────────────────────────────────────────────────── */

/* The two limits in every record, and no member that would claim a
 * position or a plaintext. Seen red with POSITION_LIMIT emptied in
 * web_frrs_report.c, and with a `"lat":null` member added to the
 * emitter group. */
static void test_record_states_its_limits(void) {
    env_open(NULL, 1);
    static const char *const Q[] = {
        "kind=bssid&addr=02:de:00:00:00:a1", "kind=sta&addr=02:de:00:00:00:12",
        "kind=ble&addr=c6:de:00:00:00:b1/1",
    };
    for (size_t i = 0; i < sizeof(Q) / sizeof(Q[0]); i++) {
        WT_EQ(get("/api/frrs/report", Q[i]), 200);
        const char *b = body_of(g_out);
        WT_HAS(b, "no location axis");
        WT_HAS(b, "sloth decrypts nothing");
        static const char *const NO[] = { "\"lat\"", "\"lon\"", "\"location\"", "\"bearing\"",
                                          "\"plaintext\"", "\"decrypted\"" };
        for (size_t k = 0; k < sizeof(NO) / sizeof(NO[0]); k++) WT_LACKS(b, NO[k]);
    }
    /* The ledger's own: the BLE advertiser's appearance and the AP's
     * regulatory envelope and Multi-Link links, from the stream alone. */
    WT_EQ(get("/api/frrs/report", "kind=ble&addr=c6:de:00:00:00:b1/1"), 200);
    WT_HAS(g_out, "\"appearance\":{\"v\":194");
    WT_EQ(get("/api/frrs/report", "kind=bssid&addr=02:de:00:00:00:a1"), 200);
    WT_HAS(g_out, "\"regulatory_country\":{\"v\":\"US\"");
    WT_HAS(g_out, "\"mld_mac\":{\"v\":\"02:de:00:00:00:b0\"");
    WT_EQ(get("/api/frrs/report", "kind=bssid&addr=02:DE:00:00:00:A1"), 200);
    WT_EQ(get("/api/frrs/report", "kind=bssid&addr=not-a-mac"), 400);
    WT_EQ(get("/api/frrs/report", "kind=ip&addr=192.0.2.1"), 400);
    env_close();
}

/* SCS's certification from the vendor research KB (§4.2's hook): the
 * entry's fcc_grantee values with their [n] and the source lines those
 * numbers name; an affiliate's registrant, a registrant without an
 * entry, an entry with no grantee and an address in no block each say
 * which and show no code. Seen red with f_cert()'s affiliate branch
 * removed (Espressif's 2AC7Z shown for 6c:3d:d8, Espressif Systems
 * (Singapore) Pte. Ltd, an affiliate), and with the used[] marking
 * dropped (the sources list empty). */
static void test_scs_certification_from_vendor_kb(void) {
    /* The four registry rows it needs, as the IEEE writes them: a table
     * of its own, so a build whose WEB_OUI_DIR has no CSVs (sloth's
     * fallback names, not the IEEE's) tests the same thing. */
    char path[TEST_TMP_MAX + 32];
    snprintf(path, sizeof(path), "%s/frrs-oui-XXXXXX", test_tmpdir());
    int fd = mkstemp(path);
    WT_ASSERT(fd >= 0);
    if (fd < 0) return;
    FILE *cf = fdopen(fd, "w");
    fputs("Registry,Assignment,Organization Name,Organization Address\n"
          "MA-L,240AC4,Espressif Inc.,Room 204 Building 2 690 Bibo Rd Shanghai CN 201203\n"
          "MA-L,6C3DD8,Espressif Systems (Singapore) Pte. Ltd,1 FUSIONOPOLIS VIEW Singapore SG 138577\n"
          "MA-L,CC6618,Adtran Inc,901 Explorer Blvd. Huntsville AL US 35806-2807\n"
          "MA-L,000000,XEROX CORPORATION,M/S 105-50C WEBSTER NY US 14580\n", cf);
    fclose(cf);
    oui_build_t b;
    oui_build_init(&b);
    WT_EQ(oui_build_csv(&b, path), 0);
    WT_EQ(oui_build_finish(&b, "ieee"), 0);
    unlink(path);
    env_open(NULL, 1);
    E.m4.oui = &b.tab;
    WT_EQ(get("/api/frrs/report", "kind=sta&addr=24:0a:c4:00:00:01"), 200);
    WT_HAS(g_out, "\"certification_fcc\":{\"v\":{\"grantee\":[\"2AC7Z (FCC-certified modules");
    WT_HAS(g_out, "ESP8684-WROOM-02C) [3]\"],\"sources\":[\"[3] ");
    WT_HAS(g_out, "\"src\":\"web/data/vendors/espressif-inc.md fcc_grantee\"");
    WT_EQ(get("/api/frrs/report", "kind=sta&addr=6c:3d:d8:00:00:01"), 200);
    WT_HAS(g_out, "\"certification_fcc\":{\"v\":null,\"why\":\"the registrant is an affiliate of "
                  "Espressif Inc.");
    WT_LACKS(g_out, "2AC7Z");
    WT_EQ(get("/api/frrs/report", "kind=sta&addr=cc:66:18:00:00:01"), 200);
    WT_HAS(g_out, "\"certification_fcc\":{\"v\":null,\"why\":\"the vendor research entry documents "
                  "no FCC grantee code\"");
    WT_EQ(get("/api/frrs/report", "kind=sta&addr=00:00:00:00:00:01"), 200);
    WT_HAS(g_out, "\"certification_fcc\":{\"v\":null,\"why\":\"no vendor research entry for this "
                  "registrant\"");
    WT_EQ(get("/api/frrs/report", "kind=sta&addr=02:de:00:00:00:12"), 200);
    WT_HAS(g_out, "\"certification_fcc\":{\"v\":null,\"why\":\"no registrant: the address is in no "
                  "OUI block\"");
    env_close();
    oui_build_free(&b);
}

/* Is name a column of table in sloth.db's DDL? */
static int ddl_has(const char *ddl, const char *table, const char *col) {
    char head[96];
    snprintf(head, sizeof(head), "CREATE TABLE IF NOT EXISTS %s (", table);
    const char *a = strstr(ddl, head);
    if (!a) return -1;                               /* not a sloth.db table */
    const char *e = strstr(a, ");");
    char w[96];
    snprintf(w, sizeof(w), "  %s ", col);
    const char *c = strstr(a, w);
    if (c && (!e || c < e)) return 1;
    /* A column a migration adds. */
    snprintf(w, sizeof(w), "ALTER TABLE %s ADD COLUMN %s ", table, col);
    return strstr(ddl, w) ? 1 : 0;
}

/* Every source a record names is real: a table.column of sloth.db's
 * DDL (src/db_schema.c, linked in), or a record and field sloth's
 * stream writes (src/jsonl.c, read from the tree), or slothweb's own.
 * Seen red with "beacon_aps.beacon_ms" misspelt "beacon_aps.beacon_msx"
 * in web_frrs_report.c, and with "beacon.tbtt_jitter_us" misspelt
 * "beacon.tbtt_jitter_usx". */
static void test_every_source_is_real(void) {
    env_open(NULL, 1);
    const char *ddl = db_schema_sql();
    FILE *jf = fopen("src/jsonl.c", "rb");
    WT_ASSERT(jf != NULL);
    static char jsonl[1 << 20];
    size_t jn = jf ? fread(jsonl, 1, sizeof(jsonl) - 1, jf) : 0;
    if (jf) fclose(jf);
    jsonl[jn] = '\0';
    static const char *const Q[] = {
        "kind=bssid&addr=02:de:00:00:00:a1", "kind=sta&addr=02:de:00:00:00:12",
        "kind=ble&addr=c6:de:00:00:00:b1/1",
    };
    int tables = 0, fields = 0, bad = 0;
    for (size_t i = 0; i < sizeof(Q) / sizeof(Q[0]); i++) {
        WT_EQ(get("/api/frrs/report", Q[i]), 200);
        for (const char *p = strstr(g_out, "\"src\":\""); p; p = strstr(p + 1, "\"src\":\"")) {
            const char *s = p + 7, *e = strchr(s, '"');
            if (!e) break;
            /* Each token word.word in the source text. */
            for (const char *t = s; t < e; t++) {
                if (!(*t >= 'a' && *t <= 'z') || (t > s && ((t[-1] >= 'a' && t[-1] <= 'z') ||
                    t[-1] == '_' || t[-1] == '.' || (t[-1] >= '0' && t[-1] <= '9'))))
                    continue;
                const char *dot = t;
                while (dot < e && ((*dot >= 'a' && *dot <= 'z') || *dot == '_' || (*dot >= '0' && *dot <= '9'))) dot++;
                if (dot >= e || *dot != '.' || dot + 1 >= e || !(dot[1] >= 'a' && dot[1] <= 'z')) continue;
                const char *ce = dot + 1;
                while (ce < e && ((*ce >= 'a' && *ce <= 'z') || *ce == '_' || (*ce >= '0' && *ce <= '9'))) ce++;
                if (ce < e && (*ce == '*' || *ce == '<' || *ce == '\\' || *ce == '.')) continue;   /* a family (link_<n>, escaped), a file */
                char tb[64], col[64];
                snprintf(tb, sizeof(tb), "%.*s", (int)(dot - t), t);
                snprintf(col, sizeof(col), "%.*s", (int)(ce - dot - 1), dot + 1);
                if (!strcmp(tb, "dev") || !strcmp(tb, "wifi") || !strcmp(col, "md") ||
                    !strcmp(col, "c") || !strcmp(col, "h")) continue;   /* slothweb's series, files */
                int h = ddl_has(ddl, tb, col);
                if (h == 1) { tables++; continue; }
                if (h == 0) {
                    fprintf(stderr, "    %s.%s is not in sloth.db's DDL\n", tb, col);
                    bad++;
                    continue;
                }
                /* A stream record: its type and its field in jsonl.c. */
                char ty[80], fl[80];
                snprintf(ty, sizeof(ty), "\"%s\"", tb);
                snprintf(fl, sizeof(fl), "\"%s\"", col);
                if (strstr(jsonl, ty) && strstr(jsonl, fl)) { fields++; continue; }
                fprintf(stderr, "    %s.%s is neither a sloth.db column nor a stream field\n", tb, col);
                bad++;
            }
        }
    }
    WT_EQ(bad, 0);
    WT_ASSERT(tables >= 30);
    WT_ASSERT(fields >= 30);
    env_close();
}

/* ── the RSSI series (Q7, owner ruling 2026-11-02) ──────────────────── */

static web_rollup_t  R_ru;
static web_tsdb_t    R_ts;
static web_metrics_t R_mx;
static web_jrec_t    R_rec;
static long long     R_now;
static long long r_clock(void *c) { (void)c; return R_now; }

/* One hand-built record, in the emitter's shape, at slothweb's time t,
 * its own ts and last_seen t too (heard now). */
static void r_line(long long t, const char *fmt, const char *addr, int sig) {
    char l[512];
    R_now = t;
    int n = snprintf(l, sizeof(l), fmt, t, addr, sig, t);
    WT_EQ(web_jl_parse(l, (size_t)n, &R_rec), WEB_JL_OK);
    web_metrics_record(&R_mx, &R_rec);
}
static const char BEACON[] = "{\"type\":\"beacon\",\"ts\":%lld,\"ssid\":\"x\",\"bssid\":\"%s\","
                             "\"signal_dbm\":%d,\"channel\":6,\"last_seen\":%lld,\"frame_count\":1}";
static const char PROBE[] = "{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":\"%s\",\"ssid\":\"x\","
                            "\"signal_dbm\":%d,\"channel\":6,\"first_seen\":1,\"last_seen\":%lld,"
                            "\"frame_count\":1}";
static const char BLEDEV[] = "{\"type\":\"ble_device\",\"ts\":%lld,\"addr\":\"%s\",\"addr_type\":1,"
                             "\"has_rssi\":1,\"rssi\":%d,\"rssi_best\":-60,\"last_seen\":%lld}";

/* The Report's signal item carries the emitter's own rf.rssi.* series:
 * the last 24 h in 48 cells of 30 min, each the mean of its samples,
 * min and max the samples' own, and where the 30 days are. A kind
 * reads its own metric only, and a window holds its own day only; with
 * no series the field says "no samples", and "not kept" is gone.
 * Absences seen red: "no samples" for the station's MAC asked as a
 * BSSID, with f_rssi()'s metric fixed at WM_RF_RSSI_STA; the AP heard
 * 25 h ago, with the window's from made to - 2 * FRRS_RSSI_WINDOW_S;
 * "not kept", with the old fnone() line put back. */
static void test_report_rssi_series(void) {
    env_open(NULL, 1);
    char err[64];
    WT_EQ(web_rollup_init(&R_ru, WEB_MAX_KEYS_MIN, 0, err, sizeof(err)), 0);
    WT_EQ(web_tsdb_init(&R_ts, &R_ru, NULL, WEB_DEFAULT_RETAIN_DAYS, 256, r_clock, NULL), 0);
    WT_EQ(web_metrics_init(&R_mx, &R_ru, r_clock, NULL), 0);
    E.m4.tsdb = &R_ts;
    E.h.tsdb = &R_ts;
    /* T is a multiple of 1800, so the window is T - 86390 .. T + 10 and
     * these land in its cells 45, 47 and 47. */
    r_line(T - 3600, BEACON, "02:de:00:00:00:a1", -70);
    r_line(T - 600, BEACON, "02:de:00:00:00:a1", -50);
    r_line(T - 60, BEACON, "02:de:00:00:00:a1", -60);
    r_line(T - 90000, BEACON, "02:de:00:00:00:a2", -40);
    r_line(T - 30, PROBE, "02:de:00:00:00:12", -61);
    r_line(T - 20, BLEDEV, "c6:de:00:00:00:b1", -80);

    WT_EQ(get("/api/frrs/report", "kind=bssid&addr=02:de:00:00:00:a1"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"series_rssi\":{\"v\":{\"metric\":\"rf.rssi.bssid\",\"key\":\"02:de:00:00:00:a1\","
              "\"tier\":\"fine\",\"unit\":\"dBm\",\"from\":1792540810,\"to\":1792627210,"
              "\"cell_s\":1800,\"cells\":[null,");
    WT_HAS(b, ",null,-70.0,null,-55.0],\"min_dbm\":-70,\"max_dbm\":-50,\"last_dbm\":-60.0,"
              "\"last_t\":1792627140,\"samples\":3,\"more\":false,\"store_error\":false,"
              "\"history\":\"/api/series?metric=rf.rssi.bssid\\u0026key=02:de:00:00:00:a1\\u0026tier=minute\"}");
    WT_HAS(b, "a sloth gauge, not a calibrated measurement");
    WT_LACKS(b, "not kept");
    WT_LACKS(b, "Q7");
    /* 48 cells: two hold the three samples, 46 are null. */
    const char *c = strstr(b, "\"cells\":[");
    int nulls = 0;
    for (const char *q = c; q && *q && *q != ']'; q++) if (!strncmp(q, "null", 4)) nulls++;
    WT_EQ(nulls, 46);

    WT_EQ(get("/api/frrs/report", "kind=sta&addr=02:de:00:00:00:12"), 200);
    WT_HAS(body_of(g_out), "\"metric\":\"rf.rssi.sta\",\"key\":\"02:de:00:00:00:12\"");
    WT_HAS(body_of(g_out), "\"min_dbm\":-61,\"max_dbm\":-61,");
    WT_EQ(get("/api/frrs/report", "kind=ble&addr=c6:de:00:00:00:b1/1"), 200);
    WT_HAS(body_of(g_out), "\"metric\":\"rf.rssi.ble\",\"key\":\"c6:de:00:00:00:b1\"");
    WT_HAS(body_of(g_out), "\"min_dbm\":-80,\"max_dbm\":-80,");
    /* The station's MAC asked as an AP: its kind's series, which it has
     * none of. */
    WT_EQ(get("/api/frrs/report", "kind=bssid&addr=02:de:00:00:00:12"), 200);
    WT_HAS(body_of(g_out), "\"series_rssi\":{\"v\":null,\"why\":\"no samples\",\"src\":\"slothweb series "
                           "rf.rssi.bssid (/api/series)");
    /* Heard 25 h ago: outside the day. */
    WT_EQ(get("/api/frrs/report", "kind=bssid&addr=02:de:00:00:00:a2"), 200);
    WT_HAS(body_of(g_out), "\"series_rssi\":{\"v\":null,\"why\":\"no samples\"");

    /* Counted on /api/health as every device key is, and bounded by the
     * device class: a 17th MAC at --web-max-keys 16 evicts the least
     * recently seen (the AP heard 25 h ago), counted. */
    WT_EQ(get("/api/health", NULL), 200);
    WT_HAS(g_out, "\"series_keys\":{\"global\":0,\"device\":4,");
    WT_HAS(g_out, "\"key_evictions\":{\"global\":0,\"device\":0,");
    for (int i = 0; i < 13; i++) {
        char a[18];
        snprintf(a, sizeof(a), "02:de:00:00:01:%02x", i);
        r_line(T - 10, BEACON, a, -45);
    }
    WT_EQ(get("/api/health", NULL), 200);
    WT_HAS(g_out, "\"series_keys\":{\"global\":0,\"device\":16,");
    WT_HAS(g_out, "\"series_key_caps\":{\"global\":1,\"device\":16,");
    WT_HAS(g_out, "\"key_evictions\":{\"global\":0,\"device\":1,");
    WT_ASSERT(!web_rollup_has(&R_ru, WM_RF_RSSI_BSSID, "02:de:00:00:00:a2"));
    WT_ASSERT(web_rollup_has(&R_ru, WM_RF_RSSI_BSSID, "02:de:00:00:00:a1"));

    /* No time series attached: the field says so, and nothing else. */
    E.m4.tsdb = NULL;
    WT_EQ(get("/api/frrs/report", "kind=bssid&addr=02:de:00:00:00:a1"), 200);
    WT_HAS(body_of(g_out), "\"series_rssi\":{\"v\":null,\"why\":\"no samples\"");
    WT_LACKS(body_of(g_out), "\"cells\"");
    E.h.tsdb = NULL;
    web_metrics_destroy(&R_mx);
    web_tsdb_destroy(&R_ts);
    web_rollup_destroy(&R_ru);
    env_close();
}

/* ── the TACDB ──────────────────────────────────────────────────────── */

static void test_tacdb_round_trip(void) {
    env_open(NULL, 1);
    if (!E.have_store) {
        WT_EQ(get("/api/frrs/tacdb", ""), 503);
        env_close();
        return;
    }
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"home\",\"kind\":\"site\"}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"office\",\"kind\":\"room\",\"parent\":1}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"OFFICE\",\"kind\":\"room\",\"parent\":1}"), 409);
    WT_HAS(g_out, "duplicate_name");
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"desk\",\"kind\":\"area\",\"parent\":2}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"jeff\",\"kind\":\"person\",\"parent\":3}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"pocket\",\"kind\":\"other\",\"parent\":4}"), 409);
    WT_HAS(g_out, "unit_depth");
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"update\",\"id\":1,\"parent\":4}"), 409);
    WT_EQ(post("/api/frrs/tacdb/platform", "{\"op\":\"create\",\"nomenclature\":\"work laptop\","
               "\"class\":\"laptop\",\"unit\":4,\"emitter_kind\":\"sta\",\"emitter_addr\":\"02:DE:00:00:00:12\"}"), 200);
    WT_HAS(g_out, "\"addr\":\"02:de:00:00:00:12\"");
    WT_EQ(post("/api/frrs/tacdb/platform", "{\"op\":\"create\",\"nomenclature\":\"other\","
               "\"emitter_kind\":\"sta\",\"emitter_addr\":\"02:de:00:00:00:12\"}"), 409);
    WT_HAS(g_out, "emitter_owned");
    WT_EQ(post("/api/frrs/tacdb/emitter", "{\"op\":\"add\",\"platform\":1,\"kind\":\"ble\","
               "\"addr\":\"02:de:00:00:00:b3/0\",\"role\":\"other\",\"label\":\"keyboard\"}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"delete\",\"id\":4}"), 409);
    WT_HAS(g_out, "unit_not_empty");
    WT_EQ(get("/api/frrs/tacdb", "unit=2"), 200);
    WT_HAS(g_out, "\"nomenclature\":\"work laptop\"");
    WT_HAS(g_out, "\"unit_path\":\"home / office / desk / jeff\"");
    WT_EQ(get("/api/frrs/tacdb", "q=b3"), 200);
    WT_EQ(json_int(body_of(g_out), "matched"), 1);
    /* The report knows the filing. */
    WT_EQ(get("/api/frrs/report", "kind=sta&addr=02:de:00:00:00:12"), 200);
    WT_HAS(g_out, "\"nomenclature\":\"work laptop\"");
    /* A suggestion dismissed is gone from the list. */
    WT_EQ(get("/api/frrs/suggest", ""), 200);
    int before = count_of(body_of(g_out), "\"token\":");
    WT_ASSERT(before >= 3);
    const char *tok = strstr(body_of(g_out), "\"token\":\"");
    char t[64] = "", b[256];
    if (tok) {
        const char *e = strchr(tok + 9, '"');
        snprintf(t, sizeof(t), "%.*s", e ? (int)(e - tok - 9) : 0, tok + 9);
    }
    snprintf(b, sizeof(b), "{\"suggest\":\"%s\"}", t);
    WT_EQ(post("/api/frrs/tacdb/dismiss", b), 200);
    WT_EQ(get("/api/frrs/suggest", ""), 200);
    WT_EQ(count_of(body_of(g_out), "\"token\":"), before - 1);
    WT_EQ(post("/api/frrs/tacdb/dismiss", "{\"suggest\":\"S1.000000000000.-.00000000\"}"), 400);
    /* Delete is reversible. */
    WT_EQ(post("/api/frrs/tacdb/platform", "{\"op\":\"delete\",\"id\":1}"), 200);
    WT_HAS(g_out, "\"deleted\":true");
    WT_EQ(post("/api/frrs/tacdb/platform", "{\"op\":\"restore\",\"id\":1}"), 200);
    WT_HAS(g_out, "\"deleted\":false");
    /* Export, then check and merge into a fresh store. */
    WT_EQ(get("/api/frrs/export", ""), 200);
    WT_HAS(g_out, "Content-Disposition: attachment");
    const char *ex = body_of(g_out);
    size_t exn = strlen(ex);
    char *copy = malloc(exn + 1);
    WT_ASSERT(copy != NULL);
    if (!copy) { env_close(); return; }
    memcpy(copy, ex, exn + 1);
    WT_HAS(copy, "\"type\":\"end\"");
    env_close();
    env_open(NULL, 1);
    WT_EQ(post_h("/api/frrs/import", "mode=check", copy, "http://127.0.0.1:8770", "application/json", NULL), 200);
    WT_HAS(g_out, "\"mode\":\"check\"");
    WT_EQ(get("/api/frrs/tacdb", ""), 200);
    WT_EQ(json_int(body_of(g_out), "matched"), 0);
    WT_EQ(post_h("/api/frrs/import", "mode=merge", copy, "http://127.0.0.1:8770", "application/json",
                 "127.0.0.2"), 200);
    WT_EQ(get("/api/frrs/tacdb", ""), 200);
    WT_EQ(json_int(body_of(g_out), "matched"), 1);
    WT_HAS(g_out, "\"unit_path\":\"home / office / desk / jeff\"");
    WT_HAS(g_out, "\"label\":\"keyboard\"");
    free(copy);
    WT_EQ(post_h("/api/frrs/import", "mode=merge", "{\"type\":\"unit\",\"id\":1,\"name\":\"x\","
                 "\"kind\":\"site\",\"evil\":1}\n", "http://127.0.0.1:8770", "application/json",
                 "127.0.0.3"), 400);
    WT_EQ(get("/api/frrs/tacdb", ""), 200);
    WT_LACKS(g_out, "\"name\":\"x\"");                /* a bad line merges nothing */
    env_close();
}

/* ── the TACDB's bounds, its import and its suggestions ─────────────── */

#ifdef WITH_SQLITE
/* SQL on a file of the test's own world (the store, or the demo's
 * sloth.db), as the hand-built rows elsewhere in the suite are. */
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

/* One stream line into the ledger, as the feed hands it. */
static void feed_line(const char *line) {
    static web_jrec_t r;
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_frrs_record(&E.f, &r);
}

/* The token of the suggestion whose text holds needle, into out. */
static void tok_before(const char *b, const char *needle, char *out, size_t cap) {
    out[0] = '\0';
    const char *at = strstr(b, needle), *tok = NULL;
    for (const char *p = strstr(b, "\"token\":\""); p && at && p < at; p = strstr(p + 1, "\"token\":\"")) tok = p + 9;
    const char *e = tok ? strchr(tok, '"') : NULL;
    if (e && (size_t)(e - tok) < cap) snprintf(out, cap, "%.*s", (int)(e - tok), tok);
}

/* An import, each from a peer of its own: the bucket is its own test. */
static int import_as(const char *mode, const char *body, int peer) {
    char q[32], p[32];
    snprintf(q, sizeof(q), "mode=%s", mode);
    snprintf(p, sizeof(p), "127.0.1.%d", peer);
    return post_h("/api/frrs/import", q, body, "http://127.0.0.1:8770", "application/json", p);
}

/* The export, copied out of g_out. */
static char *export_copy(void) {
    if (get("/api/frrs/export", "") != 200) return NULL;
    const char *ex = body_of(g_out);
    size_t n = strlen(ex);
    char *c = malloc(n + 1);
    if (c) memcpy(c, ex, n + 1);
    return c;
}

/* A file with no header line, whose lines are otherwise valid, merges
 * nothing and leaves no transaction behind: the next write succeeds.
 * Seen red with the no_header refusal removed (the first line taken as
 * the header: `if (strcmp(type, "slothweb-tacdb")) why = "no_header";`
 * deleted): the file was then accepted, 200. A merge that fails after it
 * began is rolled back and the next write succeeds; that path is
 * reached here by a trigger the test puts on the store, and was seen
 * red with `else rollback(f);` removed from frrs_import() (the next
 * write 503 store_busy, the transaction held). */
static void test_import_never_leaves_a_transaction(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    static const char HEADLESS[] =
        "{\"type\":\"unit\",\"id\":1,\"parent\":null,\"name\":\"hdrless\",\"kind\":\"site\",\"note\":\"\"}\n"
        "{\"type\":\"end\",\"lines\":2,\"complete\":true}\n";
    WT_EQ(import_as("merge", HEADLESS, 1), 400);
    WT_HAS(g_out, "no_header");
    WT_HAS(g_out, "\"ok\":false");
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"after\",\"kind\":\"site\"}"), 200);
    WT_EQ(get("/api/frrs/tacdb", ""), 200);
    WT_LACKS(g_out, "hdrless");
    /* A store error mid-merge: the second unit's insert aborts. */
    WT_EQ(sql_on(E.store_path, "CREATE TRIGGER boom BEFORE INSERT ON tacdb_unit WHEN NEW.name = 'boom'"
                               " BEGIN SELECT RAISE(ABORT, 'boom'); END;"), 0);
    static const char FAILS[] =
        "{\"type\":\"slothweb-tacdb\",\"format\":\"slothweb-tacdb\",\"version\":1}\n"
        "{\"type\":\"unit\",\"id\":1,\"parent\":null,\"name\":\"first\",\"kind\":\"site\",\"note\":\"\"}\n"
        "{\"type\":\"unit\",\"id\":2,\"parent\":null,\"name\":\"boom\",\"kind\":\"site\",\"note\":\"\"}\n"
        "{\"type\":\"end\",\"lines\":4,\"complete\":true}\n";
    WT_EQ(import_as("merge", FAILS, 2), 400);
    WT_HAS(g_out, "store_error");
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"later\",\"kind\":\"site\"}"), 200);
    WT_EQ(get("/api/frrs/tacdb", ""), 200);
    WT_LACKS(g_out, "\"name\":\"first\"");            /* rolled back whole */
    WT_HAS(g_out, "\"name\":\"later\"");
    env_close();
}

/* A file cut short, or one whose export stopped at its bound, merges
 * nothing. Seen red with the end-line requirement removed (the
 * "truncated" note after the check and `&& x.saw_end` in ok both
 * deleted): the cut file merged its unit, 200. */
static void test_import_needs_its_end(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    static const char CUT[] =
        "{\"type\":\"slothweb-tacdb\",\"format\":\"slothweb-tacdb\",\"version\":1}\n"
        "{\"type\":\"unit\",\"id\":1,\"parent\":null,\"name\":\"cut\",\"kind\":\"site\",\"note\":\"\"}\n";
    WT_EQ(import_as("merge", CUT, 1), 400);
    WT_HAS(g_out, "truncated");
    static const char SHORT[] =
        "{\"type\":\"slothweb-tacdb\",\"format\":\"slothweb-tacdb\",\"version\":1}\n"
        "{\"type\":\"unit\",\"id\":1,\"parent\":null,\"name\":\"cut\",\"kind\":\"site\",\"note\":\"\"}\n"
        "{\"type\":\"end\",\"lines\":4,\"complete\":true}\n";
    WT_EQ(import_as("merge", SHORT, 2), 400);
    WT_HAS(g_out, "truncated");
    static const char PART[] =
        "{\"type\":\"slothweb-tacdb\",\"format\":\"slothweb-tacdb\",\"version\":1}\n"
        "{\"type\":\"unit\",\"id\":1,\"parent\":null,\"name\":\"cut\",\"kind\":\"site\",\"note\":\"\"}\n"
        "{\"type\":\"end\",\"lines\":3,\"complete\":false}\n";
    WT_EQ(import_as("merge", PART, 3), 400);
    WT_HAS(g_out, "export_incomplete");
    WT_EQ(get("/api/frrs/tacdb", ""), 200);
    WT_LACKS(g_out, "\"name\":\"cut\"");
    env_close();
}

/* A unit moved under one made after it, exported and merged into a
 * fresh store, keeps its place and its platform's: the export writes
 * parents first, and the import settles any order itself. Export order
 * seen red with `ORDER BY t.path` made `ORDER BY u.id` (the child's
 * line first); the import's own order seen red, on a file written
 * child first by hand, with the rounds cut to one (`round <=
 * WEB_FRRS_UNIT_DEPTH + 1` made `round < 1`: parent_not_merged). A
 * platform whose unit did not merge is skipped, never re-filed under no
 * unit: seen red with the unit_not_merged check removed (the platform
 * merged, "unit":null). */
static void test_import_keeps_the_tree(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"child\",\"kind\":\"room\"}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"site\",\"kind\":\"site\"}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"update\",\"id\":1,\"parent\":2}"), 200);
    WT_EQ(post("/api/frrs/tacdb/platform", "{\"op\":\"create\",\"nomenclature\":\"desk phone\","
               "\"unit\":1,\"emitter_kind\":\"sta\",\"emitter_addr\":\"02:de:00:00:00:12\"}"), 200);
    char *ex = export_copy();
    WT_ASSERT(ex != NULL);
    if (!ex) { env_close(); return; }
    const char *site = strstr(ex, "\"name\":\"site\""), *child = strstr(ex, "\"name\":\"child\"");
    WT_ASSERT(site && child && site < child);
    env_close();
    env_open(NULL, 1);
    WT_EQ(import_as("merge", ex, 1), 200);
    WT_HAS(g_out, "\"skipped_n\":0");
    WT_EQ(get("/api/frrs/tacdb", ""), 200);
    WT_HAS(g_out, "\"unit_path\":\"site / child\"");
    free(ex);
    env_close();
    env_open(NULL, 1);
    static const char CHILD_FIRST[] =
        "{\"type\":\"slothweb-tacdb\",\"format\":\"slothweb-tacdb\",\"version\":1}\n"
        "{\"type\":\"unit\",\"id\":7,\"parent\":9,\"name\":\"kid\",\"kind\":\"room\",\"note\":\"\"}\n"
        "{\"type\":\"unit\",\"id\":9,\"parent\":null,\"name\":\"top\",\"kind\":\"site\",\"note\":\"\"}\n"
        "{\"type\":\"platform\",\"id\":3,\"unit\":7,\"nomenclature\":\"kid phone\",\"class\":\"phone\","
        "\"vendor\":\"\",\"note\":\"\",\"confirmed\":true,\"origin\":\"operator\"}\n"
        "{\"type\":\"platform\",\"id\":4,\"unit\":5,\"nomenclature\":\"lost phone\",\"class\":\"phone\","
        "\"vendor\":\"\",\"note\":\"\",\"confirmed\":true,\"origin\":\"operator\"}\n"
        "{\"type\":\"end\",\"lines\":6,\"complete\":true}\n";
    WT_EQ(import_as("merge", CHILD_FIRST, 2), 200);
    WT_HAS(g_out, "\"units\":2");
    WT_HAS(g_out, "{\"line\":5,\"why\":\"unit_not_merged\"}");
    WT_EQ(get("/api/frrs/tacdb", ""), 200);
    WT_HAS(g_out, "\"unit_path\":\"top / kid\"");
    WT_LACKS(g_out, "lost phone");
    env_close();
}

/* A platform of the file whose nomenclature a platform here has is
 * that platform only when one of its emitters is already filed on it;
 * else it is skipped, named, and its emitters with it. Seen red with
 * `if (!overlap)` made `if (0)` in imp_platforms() (the stranger's
 * emitter merged onto the local "laptop"). */
static void test_import_no_merge_by_name(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    WT_EQ(post("/api/frrs/tacdb/platform", "{\"op\":\"create\",\"nomenclature\":\"laptop\","
               "\"emitter_kind\":\"sta\",\"emitter_addr\":\"02:de:00:00:00:12\"}"), 200);
    static const char OTHER[] =
        "{\"type\":\"slothweb-tacdb\",\"format\":\"slothweb-tacdb\",\"version\":1}\n"
        "{\"type\":\"platform\",\"id\":1,\"unit\":null,\"nomenclature\":\"Laptop\",\"class\":\"laptop\","
        "\"vendor\":\"\",\"note\":\"\",\"confirmed\":true,\"origin\":\"operator\"}\n"
        "{\"type\":\"emitter\",\"platform\":1,\"kind\":\"sta\",\"addr\":\"02:de:00:00:00:77\","
        "\"role\":\"primary\",\"label\":\"\"}\n"
        "{\"type\":\"end\",\"lines\":4,\"complete\":true}\n";
    WT_EQ(import_as("merge", OTHER, 1), 200);
    WT_HAS(g_out, "{\"line\":2,\"why\":\"duplicate_name\"}");
    WT_HAS(g_out, "{\"line\":3,\"why\":\"platform_not_merged\"}");
    WT_EQ(get("/api/frrs/tacdb", "q=77"), 200);
    WT_EQ(json_int(body_of(g_out), "matched"), 0);
    static const char SAME[] =
        "{\"type\":\"slothweb-tacdb\",\"format\":\"slothweb-tacdb\",\"version\":1}\n"
        "{\"type\":\"platform\",\"id\":1,\"unit\":null,\"nomenclature\":\"laptop\",\"class\":\"laptop\","
        "\"vendor\":\"\",\"note\":\"\",\"confirmed\":true,\"origin\":\"operator\"}\n"
        "{\"type\":\"emitter\",\"platform\":1,\"kind\":\"sta\",\"addr\":\"02:de:00:00:00:12\","
        "\"role\":\"primary\",\"label\":\"\"}\n"
        "{\"type\":\"emitter\",\"platform\":1,\"kind\":\"ble\",\"addr\":\"02:de:00:00:00:b3/0\","
        "\"role\":\"other\",\"label\":\"mouse\"}\n"
        "{\"type\":\"end\",\"lines\":5,\"complete\":true}\n";
    WT_EQ(import_as("merge", SAME, 2), 200);
    WT_HAS(g_out, "\"emitters\":1");
    WT_EQ(get("/api/frrs/tacdb", "q=b3"), 200);
    WT_HAS(g_out, "\"nomenclature\":\"laptop\"");
    WT_HAS(g_out, "\"label\":\"mouse\"");
    env_close();
}

/* A restore keeps the tree's rules: never past four levels, never a
 * live platform in a deleted unit. Depth seen red with the restore's
 * unit_depth check removed (Y restored at depth 5); the unit seen red
 * with the restore's unit_deleted check removed (200). */
static void test_restore_keeps_the_rules(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"A\",\"kind\":\"site\"}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"B\",\"kind\":\"area\",\"parent\":1}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"C\",\"kind\":\"room\",\"parent\":2}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"X\",\"kind\":\"area\"}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"Y\",\"kind\":\"person\",\"parent\":4}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"delete\",\"id\":5}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"update\",\"id\":4,\"parent\":3}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"restore\",\"id\":5}"), 409);
    WT_HAS(g_out, "unit_depth");
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"Z\",\"kind\":\"room\"}"), 200);
    WT_EQ(post("/api/frrs/tacdb/platform", "{\"op\":\"create\",\"nomenclature\":\"in Z\",\"unit\":6}"), 200);
    WT_EQ(post("/api/frrs/tacdb/platform", "{\"op\":\"delete\",\"id\":1}"), 200);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"delete\",\"id\":6}"), 200);
    WT_EQ(post("/api/frrs/tacdb/platform", "{\"op\":\"restore\",\"id\":1}"), 409);
    WT_HAS(g_out, "unit_deleted");
    env_close();
}

/* Deleted rows count toward a bound twice the cap, so create-then-
 * delete cannot grow a table without end; the export carries live rows
 * only. Seen red with no_room()'s total test removed (`if (!rows)
 * return 0;` made `return 0;`: the create admitted, 200); the export's
 * seen red with `WHERE deleted = 0` removed from its platform query
 * (the deleted platform's name in the file). */
static void test_deleted_rows_are_bounded(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    char sql[256];
    snprintf(sql, sizeof(sql), "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < %d)"
             " INSERT INTO tacdb_unit (name, kind, created, updated, deleted) SELECT 'gone ' || i, 5, 1, 1, 1"
             " FROM n", 2 * WEB_FRRS_UNITS);
    WT_EQ(sql_on(E.store_path, sql), 0);
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"one more\",\"kind\":\"site\"}"), 507);
    WT_HAS(g_out, "tacdb_full");
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"restore\",\"id\":1}"), 200);   /* a restore adds no row */
    WT_EQ(post("/api/frrs/tacdb/platform", "{\"op\":\"create\",\"nomenclature\":\"kept\"}"), 200);
    WT_EQ(post("/api/frrs/tacdb/platform", "{\"op\":\"create\",\"nomenclature\":\"thrown away\"}"), 200);
    WT_EQ(post("/api/frrs/tacdb/platform", "{\"op\":\"delete\",\"id\":2}"), 200);
    char *ex = export_copy();
    WT_ASSERT(ex != NULL);
    WT_HAS(ex, "\"nomenclature\":\"kept\"");
    WT_LACKS(ex, "thrown away");
    WT_LACKS(ex, "gone 2\"");
    WT_LACKS(ex, "\"deleted\":");
    free(ex);
    env_close();
}

/* A string member's value, into out ("" when absent). */
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

/* An alert's descriptor, as its history names it. */
static int desc_of(const char *id, char *type, char *addr, size_t cap, long long *port,
                   long long *first) {
    char q[64];
    snprintf(q, sizeof(q), "id=%s", id);
    if (get("/api/frrs/history", q) != 200) return 0;
    const char *d = strstr(body_of(g_out), "\"descriptor\":");
    if (!d) return 0;
    json_str(d, "type", type, cap);
    json_str(d, "addr", addr, cap);
    *port = json_int(d, "port");
    *first = json_int(d, "first_seen");
    return type[0] != 0;
}

/* An import file of n triage lines on one descriptor, ts rising from
 * ts0, into b (cap); its length. */
static size_t tri_file(char *b, size_t cap, const char *type, const char *addr, long long port,
                       long long first, int n, long long ts0, const char *by, const char *peer) {
    size_t k = (size_t)snprintf(b, cap, "{\"type\":\"slothweb-tacdb\",\"format\":\"slothweb-tacdb\",\"version\":1}\n");
    for (int i = 0; i < n && k < cap; i++)
        k += (size_t)snprintf(b + k, cap - k, "{\"type\":\"triage\",\"alert_type\":\"%s\","
                              "\"addr\":\"%s\",\"port\":%lld,\"first_seen\":%lld,"
                              "\"state\":\"%s\",\"prev_state\":\"untriaged\",\"via\":\"manual\","
                              "\"basis\":\"\",\"note\":\"\",\"by\":\"%s\",\"peer\":\"%s\",\"ts\":%lld}\n",
                              type, addr, port, first, i % 2 ? "false" : "noise", by, peer, ts0 + i);
    if (k < cap) k += (size_t)snprintf(b + k, cap - k, "{\"type\":\"end\",\"lines\":%d,\"complete\":true}\n", n + 2);
    return k;
}

/* One alert's history never refuses its operator: past 64 rows it
 * folds, the first row and the newest kept, the count of the folded
 * recorded. 70 operator changes all succeed and leave 64 rows, the
 * first ("noise", the first change) among them. Seen red with the fold
 * in tri_room() replaced by the old refusal (`if (n >= WEB_FRRS_HIST_PER)
 * { *why = "history_full"; return 1; }`): the 65th change 507. */
static void test_history_folds_never_refuses(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    char id[40], b[256], q[64];
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    int ok = 0;
    for (int i = 0; i < WEB_FRRS_HIST_PER + 6; i++) {
        snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"%s\"}", id, i % 2 ? "incident" : "noise");
        ok += post("/api/frrs/triage", b) == 200;
    }
    WT_EQ(ok, WEB_FRRS_HIST_PER + 6);
    snprintf(q, sizeof(q), "id=%s", id);
    WT_EQ(get("/api/frrs/history", q), 200);
    const char *h = body_of(g_out);
    WT_EQ(json_int(h, "history_n"), WEB_FRRS_HIST_PER);
    WT_EQ(json_int(strstr(h, "\"history_cap\":"), "folded"), 6);
    /* The oldest row shown is the first change: noise, was untriaged. */
    const char *last = NULL;
    for (const char *p = strstr(h, "{\"state\":"); p; p = strstr(p + 1, "{\"state\":")) last = p;
    WT_ASSERT(last && !strncmp(last, "{\"state\":\"noise\",\"prev_state\":\"untriaged\"", 41));
    WT_HAS(last, "\"folded\":6");
    env_close();
}

/* Imported rows take at most WEB_FRRS_IMPORT_PER of an alert's history:
 * 70 imported lines on one alert merge, 8 stay, 62 fold, and the
 * operator's incident and clear after them both succeed with the fold
 * shown. Seen red with the WEB_FRRS_IMPORT_PER fold removed from
 * tri_room() (`if (n > 0 && imp && ni >= ...)` made `if (0)`): 64
 * imported rows stayed, the history full of the file's rows. */
static void test_imports_take_a_small_share(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    char id[40], type[48], addr[64], b[256], q[64];
    long long port = 0, first = 0;
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    WT_ASSERT(desc_of(id, type, addr, sizeof(addr), &port, &first));
    size_t cap = 80 * 400;
    char *f = malloc(cap);
    WT_ASSERT(f != NULL);
    if (!f) { env_close(); return; }
    tri_file(f, cap, type, addr, port, first, 70, T - 100000, "them", "192.0.2.7");
    WT_EQ(import_as("merge", f, 1), 200);
    WT_HAS(g_out, "\"triage\":70");
    snprintf(q, sizeof(q), "id=%s", id);
    WT_EQ(get("/api/frrs/history", q), 200);
    WT_EQ(count_of(body_of(g_out), "\"via\":\"import\""), WEB_FRRS_IMPORT_PER + 1);   /* + current */
    WT_EQ(json_int(strstr(body_of(g_out), "\"history_cap\":"), "folded"), 70 - WEB_FRRS_IMPORT_PER);
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"incident\"}", id);
    WT_EQ(post("/api/frrs/triage", b), 200);
    WT_HAS(g_out, "\"state\":\"incident\"");
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"untriaged\"}", id);
    WT_EQ(post("/api/frrs/triage", b), 200);
    WT_EQ(get("/api/frrs/history", q), 200);
    WT_HAS(g_out, "\"current\":{\"state\":\"untriaged\"");
    WT_EQ(json_int(body_of(g_out), "history_n"), WEB_FRRS_IMPORT_PER + 2);
    WT_EQ(json_int(strstr(body_of(g_out), "\"history_cap\":"), "folded"), 70 - WEB_FRRS_IMPORT_PER);
    /* The same file again: nothing is newer than what is here. */
    WT_EQ(import_as("merge", f, 2), 200);
    WT_HAS(g_out, "\"triage\":0");
    free(f);
    env_close();
}

/* A write that changes nothing (the state it has, no new note) is a
 * 200 with no row: a double click, or a clear of an untriaged alert,
 * never spends history. A new note on the same state is a change. Seen
 * red with `int unchanged = 0;` in post_triage() (history_n 2 after the
 * repeat, and a row for the clear of an untriaged alert). */
static void test_unchanged_write_adds_no_row(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    char id[40], b[256];
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"untriaged\"}", id);
    WT_EQ(post("/api/frrs/triage", b), 200);
    WT_HAS(g_out, "\"unchanged\":true");
    WT_HAS(g_out, "\"history_n\":0");
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\",\"note\":\"n1\"}", id);
    WT_EQ(post("/api/frrs/triage", b), 200);
    WT_HAS(g_out, "\"unchanged\":false");
    WT_EQ(post("/api/frrs/triage", b), 200);                  /* the same again */
    WT_HAS(g_out, "\"unchanged\":true");
    WT_HAS(g_out, "\"history_n\":1");
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\"}", id);
    WT_EQ(post("/api/frrs/triage", b), 200);                  /* no note: no change */
    WT_HAS(g_out, "\"history_n\":1");
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\",\"note\":\"n2\"}", id);
    WT_EQ(post("/api/frrs/triage", b), 200);                  /* a new note is one */
    WT_HAS(g_out, "\"history_n\":2");
    env_close();
}

#ifdef WITH_SQLITE
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

/* The table at its cap (lowered to 40 here) keeps taking writes: the
 * oldest superseded rows fold, imported ones first, an alert's current
 * row never; /api/health and the summary say how full it is. With
 * nothing superseded left a decided state is 507 triage_full, and a
 * clear still goes in. Seen red with the retain() call removed from
 * tri_room() (the write at the cap 507), with the clear's exception
 * removed (the clear 507), with the fold after a clear removed from
 * tri_write() (41 rows), and with `t.via = 2 DESC,` removed from
 * retain()'s order (an operator's superseded row folded before the
 * imported one). */
static void test_triage_cap_folds_and_clears(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
#ifdef WITH_SQLITE
    E.f.triage_cap = 40;
    char a[40], k[40], b[256];
    WT_ASSERT(id_of("PORT_SCAN", a, sizeof(a)));
    WT_ASSERT(id_of("KARMA_AP", k, sizeof(k)));
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"incident\"}", a);
    WT_EQ(post("/api/frrs/triage", b), 200);
    /* 36 rows of 18 other alerts, two each (one superseded): the last
     * pair imported, the rest an operator's, all older than 7 days, so
     * only the imported-first order takes the imported one first. */
    WT_EQ(sql_on(E.store_path,
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 36)"
        " INSERT INTO triage (subject, type, addr, port, first_seen, state, via, ts)"
        " SELECT 'x0:' || ((i + 1) / 2), 0, '', 0, (i + 1) / 2, 2, CASE WHEN i >= 35 THEN 2 ELSE 0 END, i"
        " FROM n"), 0);
    WT_EQ(store_int("SELECT COUNT(*) FROM triage"), 37);
    WT_EQ(get("/api/frrs/summary", ""), 200);
    WT_HAS(g_out, "\"near_cap\":true");
    WT_HAS(g_out, "\"cap\":40");
    for (int i = 0; i < 6; i++) {
        snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"%s\"}", k, i % 2 ? "false" : "noise");
        WT_EQ(post("/api/frrs/triage", b), 200);
    }
    WT_ASSERT(store_int("SELECT COUNT(*) FROM triage") <= 40);
    /* The imported superseded row went first, the alert's current rows stay. */
    WT_EQ(store_int("SELECT COUNT(*) FROM triage WHERE via = 2 AND first_seen = 18"), 1);
    WT_EQ(store_int("SELECT COUNT(*) FROM triage WHERE state = 3"), 1);
    WT_EQ(get("/api/health", ""), 200);
    WT_HAS(g_out, "\"triage_cap\":40");
    WT_ASSERT(json_int(body_of(g_out), "triage_folded") >= 3);
    /* Nothing superseded left: the two alerts' current rows and 38
     * others, one row each, the table at its cap. */
    WT_EQ(sql_on(E.store_path,
        "DELETE FROM triage WHERE subject LIKE 'x0:%';"
        "DELETE FROM triage WHERE id NOT IN (SELECT MAX(id) FROM triage"
        " GROUP BY type, addr, port, first_seen);"
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 38)"
        " INSERT INTO triage (subject, type, addr, port, first_seen, state, via, ts)"
        " SELECT 'x1:' || i, 1, '', 0, i, 2, 0, i FROM n"), 0);
    WT_EQ(store_int("SELECT COUNT(*) FROM triage"), 40);
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"incident\"}", k);
    WT_EQ(post("/api/frrs/triage", b), 507);
    WT_HAS(g_out, "triage_full");
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"untriaged\"}", a);
    WT_EQ(post("/api/frrs/triage", b), 200);              /* a clear always goes in */
    WT_HAS(g_out, "\"current\":{\"state\":\"untriaged\"");
    /* The incident it superseded folded at once: the table at its cap,
     * the alert's history one row with one folded. */
    WT_EQ(store_int("SELECT COUNT(*) FROM triage"), 40);
    char q[64];
    snprintf(q, sizeof(q), "id=%s", a);
    WT_EQ(get("/api/frrs/history", q), 200);
    WT_HAS(g_out, "\"history_n\":1,\"folded\":1");
#endif
    env_close();
}

/* An import's triage lines: at most WEB_FRRS_IMPORT_TRIAGE in one file
 * (more is refused whole, 413, nothing merged), imported rows at most
 * half the table, no ts beyond five minutes ahead, and the file's by
 * and peer kept as claims with the importer as the peer. Per file seen
 * red with the 413 made 400 in frrs_import(); the future ts with its
 * check removed from frrs_triage_import() (the line merged, 200); the
 * claims with the insert's peer and claim_peer swapped (peer
 * "192.0.2.7"). The 1,000-line import and /api/health during it are
 * measured in test_import_time_over_socket. */
static void test_import_triage_bounded(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    size_t cap = (size_t)(WEB_FRRS_IMPORT_TRIAGE + 3) * 400;
    char *b = malloc(cap);
    WT_ASSERT(b != NULL);
    if (!b) { env_close(); return; }
    char id[40], type[48], addr[64], q[64];
    long long port = 0, first = 0;
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    WT_ASSERT(desc_of(id, type, addr, sizeof(addr), &port, &first));
    /* A future ts: refused. */
    tri_file(b, cap, type, addr, port, first, 1, T + WEB_FRRS_TS_AHEAD_S + 60, "", "");
    WT_EQ(import_as("merge", b, 1), 400);
    WT_HAS(g_out, "future_ts");
    tri_file(b, cap, type, addr, port, first, 1, T + WEB_FRRS_TS_AHEAD_S - 60, "", "");
    WT_EQ(import_as("check", b, 2), 200);                 /* within the skew: taken */
    /* Claims: the file's by and peer, and this importer as the peer. */
    tri_file(b, cap, type, addr, port, first, 1, T - 50, "alice", "192.0.2.7");
    WT_EQ(import_as("merge", b, 3), 200);
    WT_HAS(g_out, "\"triage\":1");
    snprintf(q, sizeof(q), "id=%s", id);
    WT_EQ(get("/api/frrs/history", q), 200);
    WT_HAS(g_out, "\"claimed_by\":\"alice\"");
    WT_HAS(g_out, "\"claimed_peer\":\"192.0.2.7\"");
    WT_HAS(g_out, "\"peer\":\"127.0.1.3\"");
    WT_HAS(g_out, "\"by\":\"\"");
    char *ex = export_copy();                             /* exported as the claim it is */
    WT_ASSERT(ex && strstr(ex, "\"by\":\"alice\",\"peer\":\"192.0.2.7\""));
    free(ex);
    /* The imported share, full: nothing more is imported. */
    char sql[400];
    snprintf(sql, sizeof(sql), "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < %d)"
             " INSERT INTO triage (subject, type, addr, port, first_seen, state, via, ts)"
             " SELECT 'x0:' || i, 0, '', 0, i, 2, 2, 1 FROM n", WEB_FRRS_IMPORTED_CAP);
    WT_EQ(sql_on(E.store_path, sql), 0);
    tri_file(b, cap, "PORT_SCAN", "198.51.100.8", 0, 1700000000, 1, 1700000001, "", "");
    WT_EQ(import_as("merge", b, 4), 200);
    WT_HAS(g_out, "\"triage\":0");
    WT_HAS(g_out, "import_share_full");
    /* A manual triage still has its room. */
    char body[160];
    snprintf(body, sizeof(body), "{\"id\":\"%s\",\"state\":\"incident\"}", id);
    WT_EQ(post("/api/frrs/triage", body), 200);
    /* One file, past its own bound: refused whole, 413, at the check. */
    tri_file(b, cap, "PORT_SCAN", "198.51.100.9", 0, 1, WEB_FRRS_IMPORT_TRIAGE + 1, 1, "", "");
    WT_EQ(import_as("merge", b, 5), 413);
    WT_HAS(g_out, "too_many_triage");
    WT_HAS(g_out, "\"triage\":0");
    free(b);
    env_close();
}

/* The check reports what the merge would: here a unit cycle (each the
 * other's parent), which only the merge's parent-first rounds find.
 * Seen red with the check's merge run removed (frrs_import()'s
 * `if (!x.bad_line)` made `if (write && !x.bad_line)`): the check said
 * nothing of either unit, the merge skipped both. */
static void test_import_check_is_the_merge(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    static const char CYCLE[] =
        "{\"type\":\"slothweb-tacdb\",\"format\":\"slothweb-tacdb\",\"version\":1}\n"
        "{\"type\":\"unit\",\"id\":1,\"parent\":2,\"name\":\"ying\",\"kind\":\"site\",\"note\":\"\"}\n"
        "{\"type\":\"unit\",\"id\":2,\"parent\":1,\"name\":\"yang\",\"kind\":\"site\",\"note\":\"\"}\n"
        "{\"type\":\"unit\",\"id\":3,\"parent\":null,\"name\":\"fine\",\"kind\":\"site\",\"note\":\"\"}\n"
        "{\"type\":\"end\",\"lines\":5,\"complete\":true}\n";
    WT_EQ(import_as("check", CYCLE, 1), 200);
    static char chk[4096];
    snprintf(chk, sizeof(chk), "%s", body_of(g_out));
    WT_HAS(chk, "{\"line\":2,\"why\":\"parent_not_merged\"}");
    WT_HAS(chk, "{\"line\":3,\"why\":\"parent_not_merged\"}");
    WT_HAS(chk, "\"units\":1");                           /* would merge "fine" */
    WT_EQ(get("/api/frrs/tacdb", ""), 200);
    WT_LACKS(g_out, "\"name\":\"fine\"");                 /* a check writes nothing */
    WT_EQ(import_as("merge", CYCLE, 2), 200);
    const char *mg = body_of(g_out);
    WT_HAS(mg, "{\"line\":2,\"why\":\"parent_not_merged\"}");
    WT_HAS(mg, "{\"line\":3,\"why\":\"parent_not_merged\"}");
    WT_EQ(json_int(mg, "skipped_n"), json_int(chk, "skipped_n"));
    WT_EQ(get("/api/frrs/tacdb", ""), 200);
    WT_HAS(g_out, "\"name\":\"fine\"");
    env_close();
}

/* The bidirectional controls are refused in operator text as control
 * bytes are: U+202E in a note, U+2066 in a unit name. Seen red with the
 * E2 80/81 test removed from frrs_text() (both 200). U+2069's neighbour
 * U+2070 (superscript zero) and U+202F (narrow no-break space) are not
 * controls and pass. */
static void test_bidi_controls_refused(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    char id[40], b[256];
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\",\"note\":\"gpj.\xe2\x80\xae" "exe\"}", id);
    WT_EQ(post("/api/frrs/triage", b), 400);
    WT_HAS(g_out, "bad_text");
    WT_EQ(post("/api/frrs/tacdb/unit", "{\"op\":\"create\",\"name\":\"a\xe2\x81\xa6" "b\",\"kind\":\"site\"}"), 400);
    WT_HAS(g_out, "bad_text");
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\",\"note\":\"x\xe2\x81\xb0y\xe2\x80\xafz\"}", id);
    WT_EQ(post("/api/frrs/triage", b), 200);
    env_close();
}

/* The suggestion rules as §7 states them. S3: two BSSIDs one channel
 * apart in the high nibble of the last octet, or of two vendors, are
 * not one AP (seen red with strncmp's 16 made 15, and with the vendor
 * test removed); one pair differing in the low nibble with one vendor
 * is (the control). S1: a sloth.db row the stream gave no confidence
 * for is not suggested (seen red with the test made `conf >= 0 &&
 * (...)`, the pre-#94 gap rule), and the earlier-seen address is the
 * primary (seen red with b_first ignored: the later one first). S2: an
 * AP MLD is one kind on every link, so its two confirms make one
 * platform (seen red with the per-link kind restored in the
 * suggestion, `ap || (lb && lb->has_b)`, and with the confirm's
 * `ap = mld_is_ap(f, a)` made the pair's own beacons). */
static void test_suggestion_rules(void) {
    env_open(NULL, 1);
    if (!E.have_store || !E.m4.sdb) { env_close(); return; }
    WT_EQ(sql_on(E.sdb_path,
        "INSERT INTO beacon_aps (bssid, channel, vendor, first_seen, last_seen) VALUES"
        " ('02:de:00:00:01:15', 11, 'V', 1, 2), ('02:de:00:00:01:25', 11, 'V', 1, 2),"
        " ('02:de:00:00:01:31', 11, 'V', 1, 2), ('02:de:00:00:01:32', 11, 'W', 1, 2),"
        " ('02:de:00:00:01:41', 11, 'V', 1, 2), ('02:de:00:00:01:42', 11, 'V', 1, 2);"
        "INSERT INTO seqnum_correlations (mac_a, mac_b, mac_a_random, mac_b_random, gap, dt_ms,"
        " a_count, b_count, first_seen, last_seen) VALUES"
        " ('06:de:00:00:05:01', '06:de:00:00:05:02', 1, 1, 3, 1000, 10, 10, 1, 2),"
        " ('06:de:00:00:06:01', '06:de:00:00:06:02', 1, 1, 3, 1000, 10, 10, 1, 2);"), 0);
    feed_line("{\"type\":\"seqnum_correlation\",\"ts\":2,\"mac_a\":\"06:de:00:00:06:01\","
              "\"mac_b\":\"06:de:00:00:06:02\",\"gap\":3,\"fwd_gap\":3,\"confidence\":72,"
              "\"a_is_earlier\":0}");
    feed_line("{\"type\":\"beacon\",\"ts\":2,\"bssid\":\"02:de:00:00:0c:01\",\"ssid\":\"mld\"}");
    feed_line("{\"type\":\"wifi_mld\",\"ts\":2,\"mld_mac\":\"02:de:00:00:0c:b0\",\"link_count\":2,"
              "\"link_0_mac\":\"02:de:00:00:0c:01\",\"link_1_mac\":\"02:de:00:00:0c:02\"}");
    WT_EQ(get("/api/frrs/suggest", ""), 200);
    const char *b = body_of(g_out);
    WT_LACKS(b, "\"a\":\"02:de:00:00:01:15\"");
    WT_LACKS(b, "\"a\":\"02:de:00:00:01:31\"");
    WT_HAS(b, "\"a\":\"02:de:00:00:01:41\",\"b\":\"02:de:00:00:01:42\"");
    WT_LACKS(b, "06:de:00:00:05:01");
    WT_HAS(b, "\"a\":\"06:de:00:00:06:02\",\"b\":\"06:de:00:00:06:01\"");
    WT_HAS(b, "\"kind\":\"bssid\",\"a\":\"02:de:00:00:0c:b0\",\"b\":\"02:de:00:00:0c:01\"");
    WT_HAS(b, "\"kind\":\"bssid\",\"a\":\"02:de:00:00:0c:b0\",\"b\":\"02:de:00:00:0c:02\"");
    /* Both MLD pairs confirmed: one platform. */
    char t1[64], t2[64], body[160];
    tok_before(b, "\"a\":\"02:de:00:00:0c:b0\",\"b\":\"02:de:00:00:0c:01\"", t1, sizeof(t1));
    tok_before(b, "\"a\":\"02:de:00:00:0c:b0\",\"b\":\"02:de:00:00:0c:02\"", t2, sizeof(t2));
    WT_ASSERT(t1[0] && t2[0]);
    snprintf(body, sizeof(body), "{\"op\":\"confirm\",\"suggest\":\"%s\"}", t1);
    WT_EQ(post("/api/frrs/tacdb/platform", body), 200);
    long long p1 = json_int(body_of(g_out), "id");
    snprintf(body, sizeof(body), "{\"op\":\"confirm\",\"suggest\":\"%s\"}", t2);
    WT_EQ(post("/api/frrs/tacdb/platform", body), 200);
    WT_EQ(json_int(body_of(g_out), "id"), p1);
    env_close();
}
#endif

/* ── over real sockets ──────────────────────────────────────────────── */

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

static int srv_start(running_t *r, int read_only) {
    web_config_t c;
    web_config_defaults(&c);
    c.bind_port = 0;
    c.timeout_ms = 2000;
    c.linger_ms = 200;
    c.read_only = read_only;
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

static int dial(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { 4, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    return fd;
}

static size_t read_all(int fd, char *out, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = recv(fd, out + n, cap - 1 - n, 0);
        if (r <= 0) break;
        n += (size_t)r;
    }
    out[n] = '\0';
    return n;
}

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* A write end to end: the body in two sends, after the headers. */
static void test_post_over_socket(void) {
    env_open(NULL, 1);
    running_t r;
    WT_EQ(srv_start(&r, 0), 0);
    if (!r.s) { env_close(); return; }
    uint16_t port = web_server_port(r.s);
    char id[40], body[200], req[1024];
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    int bl = snprintf(body, sizeof(body), "{\"id\":\"%s\",\"state\":\"incident\",\"by\":\"sock\"}", id);
    int hl = snprintf(req, sizeof(req), "POST /api/frrs/triage HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                      "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n"
                      "Content-Length: %d\r\n\r\n", port, port, bl);
    int fd = dial(port);
    WT_ASSERT(fd >= 0);
    if (fd >= 0) {
        send(fd, req, (size_t)hl, MSG_NOSIGNAL);
        send(fd, body, 10, MSG_NOSIGNAL);
        usleep(50000);
        send(fd, body + 10, (size_t)bl - 10, MSG_NOSIGNAL);
        read_all(fd, g_out, sizeof(g_out));
        close(fd);
    }
    WT_HAS(g_out, E.have_store ? "HTTP/1.1 200 OK\r\n" : "HTTP/1.1 503");
    if (E.have_store) WT_HAS(g_out, "\"by\":\"sock\"");
    /* A POST to a path that writes nothing is the 405 it always was. */
    hl = snprintf(req, sizeof(req), "POST /api/alerts HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                  "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n"
                  "Content-Length: 2\r\n\r\n{}", port, port);
    fd = dial(port);
    if (fd >= 0) {
        send(fd, req, (size_t)hl, MSG_NOSIGNAL);
        read_all(fd, g_out, sizeof(g_out));
        close(fd);
    }
    WT_HAS(g_out, "HTTP/1.1 405");
    WT_HAS(g_out, "Allow: GET, HEAD\r\n");
    srv_stop(&r);
    env_close();
}

/* An oversize body is refused before a byte of it is read, and the
 * socket closed at once rather than drained. Seen red with the bound
 * compared as `> max * 1024` in conn_begin_body() (the server then
 * waited for the body, and answered 408 at its timeout). */
static void test_oversize_body_refused_unread(void) {
    env_open(NULL, 1);
    running_t r;
    WT_EQ(srv_start(&r, 0), 0);
    if (!r.s) { env_close(); return; }
    uint16_t port = web_server_port(r.s);
    char req[512];
    int hl = snprintf(req, sizeof(req), "POST /api/frrs/triage HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                      "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n"
                      "Content-Length: %d\r\n\r\n", port, port, WEB_POST_MAX + 1);
    int fd = dial(port);
    WT_ASSERT(fd >= 0);
    long long t0 = mono_ms();
    if (fd >= 0) {
        send(fd, req, (size_t)hl, MSG_NOSIGNAL);
        read_all(fd, g_out, sizeof(g_out));
        close(fd);
    }
    WT_HAS(g_out, "HTTP/1.1 413 Content Too Large\r\n");
    WT_ASSERT(mono_ms() - t0 < 1000);
    /* No Content-Length: 411; a Transfer-Encoding: 400. */
    hl = snprintf(req, sizeof(req), "POST /api/frrs/triage HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                  "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n\r\n", port, port);
    fd = dial(port);
    if (fd >= 0) { send(fd, req, (size_t)hl, MSG_NOSIGNAL); read_all(fd, g_out, sizeof(g_out)); close(fd); }
    WT_HAS(g_out, "HTTP/1.1 411");
    hl = snprintf(req, sizeof(req), "POST /api/frrs/triage HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                  "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n"
                  "Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n", port, port);
    fd = dial(port);
    if (fd >= 0) { send(fd, req, (size_t)hl, MSG_NOSIGNAL); read_all(fd, g_out, sizeof(g_out)); close(fd); }
    WT_HAS(g_out, "HTTP/1.1 400");
    web_stats_t st;
    web_server_stats(r.s, &st);
    WT_EQ(st.status_413, 1);
    srv_stop(&r);
    env_close();
}

/* A body's deadline is the timeout plus its length at
 * WEB_BODY_MIN_BPS: a 64 KiB import sent steadily over 3.2 s, past the
 * 2 s timeout but above the floor, is answered; a client dripping a
 * byte every 100 ms is cut off at its bound (2 s + 4,000 B at 16 KiB/s),
 * 408. The first seen red with the C_BODY deadline line removed from
 * conn_begin_body() (the import 408 at 2 s, from accept). */
static void test_body_deadline_scales(void) {
    env_open(NULL, 1);
    running_t r;
    WT_EQ(srv_start(&r, 0), 0);
    if (!r.s) { env_close(); return; }
    uint16_t port = web_server_port(r.s);
    char req[512];
    enum { BODY = 65536, STEP = 8192 };
    static char nl[BODY];
    memset(nl, '\n', sizeof(nl));
    int hl = snprintf(req, sizeof(req), "POST /api/frrs/import?mode=check HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                      "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n"
                      "Content-Length: %d\r\n\r\n", port, port, BODY);
    int fd = dial(port);
    WT_ASSERT(fd >= 0);
    struct timeval tv = { 15, 0 };
    if (fd >= 0) {
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        send(fd, req, (size_t)hl, MSG_NOSIGNAL);
        for (int off = 0; off < BODY; off += STEP) {
            usleep(400000);
            send(fd, nl + off, STEP, MSG_NOSIGNAL);
        }
        read_all(fd, g_out, sizeof(g_out));
        close(fd);
    }
    WT_LACKS(g_out, "HTTP/1.1 408");
    WT_HAS(g_out, E.have_store ? "HTTP/1.1 400" : "HTTP/1.1 503");   /* answered: no header line */
    hl = snprintf(req, sizeof(req), "POST /api/frrs/triage HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                  "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n"
                  "Content-Length: 4000\r\n\r\n", port, port);
    fd = dial(port);
    long long t0 = mono_ms(), t1 = t0;
    if (fd >= 0) {
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        send(fd, req, (size_t)hl, MSG_NOSIGNAL);
        /* A byte every 100 ms until the server closes (the send fails). */
        for (int i = 0; i < 100; i++) {
            usleep(100000);
            if (send(fd, " ", 1, MSG_NOSIGNAL) != 1) break;
            char c;
            if (recv(fd, &c, 1, MSG_PEEK | MSG_DONTWAIT) >= 0) break;
        }
        read_all(fd, g_out, sizeof(g_out));
        t1 = mono_ms();
        close(fd);
    }
    WT_HAS(g_out, "HTTP/1.1 408");
    WT_ASSERT(t1 - t0 < 6000);
    srv_stop(&r);
    env_close();
}

/* The 1,000-line import (WEB_FRRS_IMPORT_TRIAGE, the most one file may
 * carry) over a socket, and /api/health asked while it runs: both
 * timed and printed, the figures the spec quotes (§14). An import runs
 * on the HTTP thread, so the health answer waits for it; the bound per
 * file is what keeps that wait short. */
#ifdef WITH_SQLITE
typedef struct { uint16_t port; long long ms; int ok; } health_probe_t;
static void *health_probe(void *arg) {
    health_probe_t *h = arg;
    usleep(50000);
    char req[256], out[8192];
    int n = snprintf(req, sizeof(req), "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n\r\n", h->port);
    long long t0 = mono_ms();
    int fd = dial(h->port);
    if (fd < 0) return NULL;
    struct timeval tv = { 60, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    send(fd, req, (size_t)n, MSG_NOSIGNAL);
    read_all(fd, out, sizeof(out));
    close(fd);
    h->ms = mono_ms() - t0;
    h->ok = strstr(out, "HTTP/1.1 200") != NULL;
    return NULL;
}

static void test_import_time_over_socket(void) {
    env_open(NULL, 1);
    if (!E.have_store) { env_close(); return; }
    running_t r;
    WT_EQ(srv_start(&r, 0), 0);
    if (!r.s) { env_close(); return; }
    uint16_t port = web_server_port(r.s);
    size_t cap = (size_t)(WEB_FRRS_IMPORT_TRIAGE + 3) * 400;
    char *b = malloc(cap);
    WT_ASSERT(b != NULL);
    if (!b) { srv_stop(&r); env_close(); return; }
    /* A store three quarters full (15,000 operator rows), where the
     * per-line table counts first built cost the most; then 100 alerts,
     * 10 lines each, the per-alert share folding as it goes. */
    WT_EQ(sql_on(E.store_path, "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n"
                               " WHERE i < 15000) INSERT INTO triage (subject, type, addr, port,"
                               " first_seen, state, via, ts) SELECT 'x2:' || i, 2, '', 0, i, 2, 0, i"
                               " FROM n"), 0);
    size_t k = (size_t)snprintf(b, cap, "{\"type\":\"slothweb-tacdb\",\"format\":\"slothweb-tacdb\",\"version\":1}\n");
    for (int i = 0; i < WEB_FRRS_IMPORT_TRIAGE; i++)
        k += (size_t)snprintf(b + k, cap - k, "{\"type\":\"triage\",\"alert_type\":\"PORT_SCAN\","
                              "\"addr\":\"198.51.100.%d\",\"port\":0,\"first_seen\":1700000000,"
                              "\"state\":\"noise\",\"prev_state\":\"untriaged\",\"via\":\"manual\","
                              "\"basis\":\"\",\"note\":\"\",\"by\":\"\",\"peer\":\"\",\"ts\":%d}\n",
                              i % 100, 1700000001 + i);
    k += (size_t)snprintf(b + k, cap - k, "{\"type\":\"end\",\"lines\":%d,\"complete\":true}\n",
                          WEB_FRRS_IMPORT_TRIAGE + 2);
    char req[512];
    int hl = snprintf(req, sizeof(req), "POST /api/frrs/import?mode=merge HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                      "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n"
                      "Content-Length: %zu\r\n\r\n", port, port, k);
    health_probe_t hp = { port, -1, 0 };
    pthread_t th;
    int fd = dial(port);
    WT_ASSERT(fd >= 0);
    long long t0 = mono_ms(), t1 = t0;
    if (fd >= 0) {
        struct timeval tv = { 60, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        send(fd, req, (size_t)hl, MSG_NOSIGNAL);
        send(fd, b, k, MSG_NOSIGNAL);
        int started = pthread_create(&th, NULL, health_probe, &hp) == 0;
        read_all(fd, g_out, sizeof(g_out));
        t1 = mono_ms();
        close(fd);
        if (started) pthread_join(th, NULL);
    }
    WT_HAS(g_out, "HTTP/1.1 200");
    WT_HAS(g_out, "\"triage\":1000");
    WT_ASSERT(hp.ok);
    fprintf(stderr, "  frrs: %d-line import into 15,000 rows %lld ms; /api/health asked 50 ms "
            "into it answered in %lld ms\n", WEB_FRRS_IMPORT_TRIAGE, t1 - t0, hp.ms);
    WT_ASSERT(t1 - t0 < 30000);
    free(b);
    srv_stop(&r);
    env_close();
}
#endif

/* --web-read-only: every POST is 405 Allow: GET, HEAD, the write paths
 * included, and the reads stay. Seen red with the read_only branch
 * taken out of conn_begin_body() (the router's own 405 read_only then
 * carried no Allow: GET, HEAD). */
static void test_read_only_over_socket(void) {
    env_open(NULL, 0);
    running_t r;
    WT_EQ(srv_start(&r, 1), 0);
    if (!r.s) { env_close(); return; }
    uint16_t port = web_server_port(r.s);
    char id[40], body[200], req[1024];
    WT_ASSERT(id_of("PORT_SCAN", id, sizeof(id)));
    int bl = snprintf(body, sizeof(body), "{\"id\":\"%s\",\"state\":\"noise\"}", id);
    int hl = snprintf(req, sizeof(req), "POST /api/frrs/triage HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                      "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n"
                      "Content-Length: %d\r\n\r\n%s", port, port, bl, body);
    int fd = dial(port);
    if (fd >= 0) { send(fd, req, (size_t)hl, MSG_NOSIGNAL); read_all(fd, g_out, sizeof(g_out)); close(fd); }
    WT_HAS(g_out, "HTTP/1.1 405");
    WT_HAS(g_out, "Allow: GET, HEAD\r\n");
    hl = snprintf(req, sizeof(req), "GET /api/frrs/summary HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n\r\n", port);
    fd = dial(port);
    if (fd >= 0) { send(fd, req, (size_t)hl, MSG_NOSIGNAL); read_all(fd, g_out, sizeof(g_out)); close(fd); }
    WT_HAS(g_out, "HTTP/1.1 200 OK");
    WT_HAS(g_out, "\"writes\":false");
    WT_HAS(g_out, E.have_store ? "\"rows\":0" : "\"rows\":null");
    srv_stop(&r);
    env_close();
}

/* ── the page ───────────────────────────────────────────────────────── */

/* frrs.js's own part of the page: no sink that parses markup, no
 * attribute written from a value, and the hook points app.js calls.
 * Seen red with `box.innerHTML = ""` added to clear() in frrs.js. */
static void test_page_module(void) {
    const char *p = (const char *)web_page;
    const char *a = strstr(p, "var SlothFrrs = (function () {");
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
        "eval(", "new Function", ".href =", ".src =", "createElement(\"input\")",
    };
    for (size_t i = 0; i < sizeof(SINK) / sizeof(SINK[0]); i++) WT_LACKS(m, SINK[i]);
    WT_HAS(m, "credentials: \"omit\"");
    WT_HAS(m, "\"Content-Type\": \"application/json\"");
    /* --web-read-only's 405 is the server's plain one: told as read-only,
     * not as a bare status. */
    WT_HAS(m, "if (r.status === 405) {");
    WT_HAS(m, "throw new Error(\"read_only\");");
    /* An alert page loaded directly draws its button from the history's
     * own recommendation. */
    WT_HAS(m, "S.rec[S.types[id]] = h.recommend;");
    /* A row holding buttons is no longer a link. */
    WT_HAS(m, "li.role = \"group\";");
    /* The recommendation button: the bar's own words when an assessment
     * does not meet it, and a short label for phone width. */
    WT_HAS(m, "\"no automatic triage: \"");
    WT_HAS(m, "el(\"span\", \"tri-short\", sbl)");
    /* The Report's RSSI series is drawn as text: draw_sparkline_at()'s
     * glyphs and the heat ramp's classes, each from a fixed table and
     * graded by glyph.js's port of the TUI's level, never a value of the
     * answer as markup, a class or an attribute (the sinks above hold
     * this function too: seen red with `v.innerHTML = s.history` added
     * to rssiSpark()). */
    WT_HAS(m, "var SPARK = [\"_\", \"\\u2581\", \"\\u2582\", \"\\u2583\", \"\\u2584\", \"\\u2585\", "
              "\"\\u2586\", \"\\u2587\", \"\\u2588\"];");
    WT_HAS(m, "var SPARK_CLS = { \"--tui-dim\": \"d-dim\", \"--tui-normal\": \"d-normal\", \"--heat-1\": \"h1\",");
    WT_HAS(m, "glyph.level(lift(cells[i]), max)");
    WT_HAS(m, "line.appendChild(el(\"span\", SPARK_CLS[tk] || \"d-normal\", SPARK[l] || \"_\"));");
    WT_HAS(m, "if (k === \"series_rssi\" && f.v && typeof f.v === \"object\" && Array.isArray(f.v.cells)) {");
    WT_HAS(m, "a sloth gauge, not a calibrated measurement");
    free(m);
    /* At 480 px and under the short label shows and the long one does
     * not, so the row's last button is never cut off at 393 px (seen
     * cut off there before; re-screenshot at 393 px, review of 2026-11-02).
     * Seen red with the media block removed from frrs.css. */
    const char *mq = strstr(p, ".tri-rec .tri-short { display: none; }");
    const char *mw = mq ? strstr(mq, "@media (max-width: 480px) {") : NULL;
    WT_ASSERT(mq && mw && strstr(mw, ".tri-rec .tri-long { display: none; }") &&
              strstr(mw, ".tri-rec .tri-short { display: inline; }"));
    /* Every place a linked alert row is drawn reaches the hook through
     * alertLink(), which checks the id first: the Overview, History, the
     * drawer, and an alert page's runs and other alerts. */
    const char *al = strstr(p, "function alertLink(li, id) {");
    const char *re = al ? strstr(al, "ALERT_ID_RE.test(id)") : NULL;
    const char *hk = al ? strstr(al, "SlothFrrs.link(li, id)") : NULL;
    WT_ASSERT(al && re && hk && re < hk);
    /* the definition, its five callers, and frrs.js's header naming it */
    WT_EQ(count_of(p, "alertLink(li, "), 7);
    /* Each hook point, one guarded call in app.js. */
    static const char *const HOOK[] = {
        "if (window.SlothFrrs) SlothFrrs.link(li, id);",
        "if (window.SlothFrrs) SlothFrrs.q(p);",
        "row.appendChild(window.SlothFrrs ? SlothFrrs.cell(a, row) : el(\"span\", \"d-dim\", \"-\"));",
        "if (window.SlothFrrs) SlothFrrs.show(v, VP);",
        "if (window.SlothFrrs) SlothFrrs.mountDrawer(mac, j);",
        "if (window.SlothFrrs) SlothFrrs.mountAlert(j);",
        "if (window.SlothFrrs) SlothFrrs.init({",
    };
    for (size_t i = 0; i < sizeof(HOOK) / sizeof(HOOK[0]); i++) WT_EQ(count_of(p, HOOK[i]), 1);
    static const char *const IDS[] = {
        "id=\"nav-tacdb\"", "id=\"v-tacdb\"", "id=\"frrs-alert-triage\"", "id=\"frrs-alert\"",
        "id=\"frrs-drawer\"", "id=\"k-alerts-triaged\"", "id=\"al-triage\"", "id=\"bundle-btn-tacdb\"",
    };
    for (size_t i = 0; i < sizeof(IDS) / sizeof(IDS[0]); i++) WT_HAS(p, IDS[i]);
    /* The location slice's elements are not this module's, but sit
     * beside its own: loc-alert after frrs-alert and above the proof
     * (whose capture stays the page's last), loc-drawer after
     * frrs-drawer. */
    WT_EQ(count_of(p, "id=\"loc-alert\""), 1);
    WT_EQ(count_of(p, "id=\"loc-drawer\""), 1);
    const char *fa = strstr(p, "id=\"frrs-alert\"");
    const char *la = strstr(p, "id=\"loc-alert\"");
    const char *ea = strstr(p, "id=\"ev-alert\"");
    WT_ASSERT(fa && la && ea && fa < la && la < ea);
    const char *fd = strstr(p, "id=\"frrs-drawer\"");
    const char *ld = strstr(p, "id=\"loc-drawer\"");
    WT_ASSERT(fd && ld && fd < ld);
}

/* The ledger is bounded: past its BSSIDs the least recently seen goes,
 * counted. */
static void test_ledger_bounded(void) {
    static web_frrs_t f;
    char err[256];
    WT_EQ(web_frrs_init(&f, NULL, NULL, 1, err, sizeof(err)), 0);
    web_jrec_t *r = malloc(sizeof(*r));
    WT_ASSERT(r != NULL);
    for (int i = 0; r && i < WEB_FRRS_LEDGER_BSSID + 10; i++) {
        char l[200];
        int n = snprintf(l, sizeof(l), "{\"type\":\"beacon\",\"ts\":%d,\"bssid\":\"02:00:00:00:%02x:%02x\","
                         "\"ssid\":\"x\",\"channel\":1}", i + 1, i / 256, i % 256);
        if (web_jl_parse(l, (size_t)n, r) == WEB_JL_OK) web_frrs_record(&f, r);
    }
    free(r);
    web_frrs_stats_t st;
    web_frrs_stats(&f, &st);
    WT_EQ(st.ledger_evictions, 10);
    WT_EQ(f.led->nbss, WEB_FRRS_LEDGER_BSSID);
    WT_ASSERT(frrs_led_bss(&f, "02:00:00:00:00:00") == NULL);
    WT_ASSERT(frrs_led_bss(&f, "02:00:00:00:02:09") != NULL);
    web_frrs_destroy(&f);
}

/* The request parser's half: POST is a request only on a write path,
 * with the write path's headers kept; a doubled Content-Length that
 * disagrees, or a malformed one, is marked; the body is not read here. */
static void test_http_post_parse(void) {
    web_req_t rq;
    static const char A[] = "POST /api/frrs/triage HTTP/1.1\r\nHost: 127.0.0.1:8770\r\n"
                            "Origin: http://127.0.0.1:8770\r\nContent-Type: application/json\r\n"
                            "Content-Length: 11\r\nSec-Fetch-Site: same-origin\r\n\r\n{\"id\":\"d1\"}";
    WT_EQ(web_http_parse(A, sizeof(A) - 1, &rq), WEB_HTTP_ROUTE);
    WT_EQ(rq.is_post, 1);
    WT_EQ(rq.content_length, 11);
    WT_HAS(rq.origin, "http://127.0.0.1:8770");
    WT_HAS(rq.ctype, "application/json");
    WT_HAS(rq.fetch_site, "same-origin");
    WT_EQ((long long)rq.hdr_len, (long long)(sizeof(A) - 1 - 11));
    static const char B[] = "POST /api/alerts HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}";
    WT_EQ(web_http_parse(B, sizeof(B) - 1, &rq), 405);
    static const char C[] = "POST /api/frrs/triage HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n"
                            "Content-Length: 3\r\n\r\n";
    WT_EQ(web_http_parse(C, sizeof(C) - 1, &rq), WEB_HTTP_ROUTE);
    WT_EQ(rq.content_length, -2);
    static const char D[] = "POST /api/frrs/triage HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1x\r\n\r\n";
    WT_EQ(web_http_parse(D, sizeof(D) - 1, &rq), WEB_HTTP_ROUTE);
    WT_EQ(rq.content_length, -2);
    static const char E2[] = "PUT /api/frrs/triage HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    WT_EQ(web_http_parse(E2, sizeof(E2) - 1, &rq), 405);
    static const char F[] = "post /api/frrs/triage HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    WT_EQ(web_http_parse(F, sizeof(F) - 1, &rq), 405);
}

void run_frrs_tests(void) {
    WT_RUN(test_http_post_parse);
    WT_RUN(test_rate_limit);
    WT_RUN(test_ledger_bounded);
    WT_RUN(test_page_module);
    WT_RUN(test_triage_round_trip);
    WT_RUN(test_triaged_out_is_counted_not_dropped);
    WT_RUN(test_cross_origin_refused);
    WT_RUN(test_body_rules);
    WT_RUN(test_get_cannot_write);
#ifdef WITH_SQLITE
    WT_RUN(test_no_credential_and_no_stream_string_stored);
    WT_RUN(test_finding_set_once);
#endif
    WT_RUN(test_follow_recommended);
    WT_RUN(test_recommend_from_the_shipped_assessments);
    WT_RUN(test_record_states_its_limits);
    WT_RUN(test_scs_certification_from_vendor_kb);
    WT_RUN(test_every_source_is_real);
    WT_RUN(test_report_rssi_series);
    WT_RUN(test_tacdb_round_trip);
#ifdef WITH_SQLITE
    WT_RUN(test_import_never_leaves_a_transaction);
    WT_RUN(test_import_needs_its_end);
    WT_RUN(test_import_keeps_the_tree);
    WT_RUN(test_import_no_merge_by_name);
    WT_RUN(test_restore_keeps_the_rules);
    WT_RUN(test_deleted_rows_are_bounded);
    WT_RUN(test_import_triage_bounded);
    WT_RUN(test_history_folds_never_refuses);
    WT_RUN(test_imports_take_a_small_share);
    WT_RUN(test_unchanged_write_adds_no_row);
    WT_RUN(test_triage_cap_folds_and_clears);
    WT_RUN(test_import_check_is_the_merge);
    WT_RUN(test_bidi_controls_refused);
    WT_RUN(test_suggestion_rules);
#endif
    WT_RUN(test_post_over_socket);
    WT_RUN(test_oversize_body_refused_unread);
    WT_RUN(test_read_only_over_socket);
    WT_RUN(test_body_deadline_scales);
#ifdef WITH_SQLITE
    WT_RUN(test_import_time_over_socket);
#endif
}
