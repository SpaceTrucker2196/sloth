/* G8's data (#171 V4; docs/web-visual-spec.md F14, §5 G8): the stream's
 * twin_episode links kept by web_chain.c, and /api/wifi/chain through
 * the route table without a socket: a BSSID's deauth frames from the
 * rollup, its other stages and associations from a sloth.db generated
 * from sloth's own DDL (sdb_gen.c), and the links from the stream, on
 * the pinned clock SDB_NOW. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_chain.h"
#include "web_ingest.h"
#include "web_routes.h"
#include "web_series.h"
#include "web_slothdb.h"
#include "web_store.h"
#include "web_tsdb.h"
#include "web_wifi.h"
#include "wtest.h"
#include "wt_tmp.h"

#define T SDB_NOW

static char g_out[65536];
static web_jrec_t R;
static web_chain_t C;

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static int route(const web_health_t *h, const char *path, const char *query) {
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "%s", path);
    snprintf(rq.query, sizeof(rq.query), "%s", query);
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    if (web_route(&rq, h, 1, g_out, sizeof(g_out), &r) != 0) return -1;
    g_out[r.out_len] = '\0';
    return r.status;
}

/* One twin_episode as sloth writes it (docs/wiki/jsonl-schema.md),
 * fed to C. extra is spliced in before the closing brace. */
static void episode(long long ts, const char *real, const char *twin, int attack,
                    int attributed, const char *extra) {
    char line[512];
    snprintf(line, sizeof(line),
             "{\"type\":\"twin_episode\",\"ts\":%lld,\"ssid\":\"Cafe-Net\",\"real_bssid\":\"%s\","
             "\"twin_bssid\":\"%s\",\"enc\":\"WPA2\",\"real_rssi\":-70,\"twin_rssi\":-45,"
             "\"rssi_swing_dbm\":25,\"attack_in_progress\":%d,\"attacker_oui\":0,"
             "\"hash_mismatch\":0,\"attributed\":%d%s}",
             ts, real, twin, attack, attributed, extra ? extra : "");
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_chain_record(&C, &R);
}

#define A1 "aa:00:00:00:00:01"
#define B2 "bb:00:00:00:00:02"
#define E5 "ee:00:00:00:00:05"

/* A pair is one entry whichever half each record names first (an
 * unattributed pair is only byte order, and attribution can swap it):
 * seen red with the pair keyed on (real, twin) as written (two entries,
 * the attribution on the second only). The taint is the first record
 * that carried it (seen red with it kept as the newest). A 1 is an
 * integer: a string "1" is no taint and no attribution (seen red with
 * one() taking the string "1" too). The links are the pairs naming the
 * BSSID (seen red with the name test removed: cc:..:03 had one) whose
 * records reach the window (seen red with the overlap test removed: a
 * window before the first record and one after the last had it). A bad
 * address, a pair of one BSSID and a record with no ts are refused and
 * counted. The SSID is not kept: the table has no member for it. */
static void test_pairs(void) {
    WT_EQ(web_chain_init(&C), 0);
    WT_EQ(web_chain_since(&C), 0);
    episode(T - 300, A1, B2, 0, 0, ",\"confidence\":20");
    episode(T - 290, B2, A1, 0, 1, ",\"confidence\":60");
    episode(T - 280, B2, A1, 1, 1, ",\"confidence\":70");
    episode(T - 270, B2, A1, 1, 1, ",\"confidence\":70");
    WT_EQ(C.n, 1);
    WT_EQ((long long)C.records, 4);
    web_chain_pair_t lk[WEB_CHAIN_LINKS];
    long long since = 0;
    WT_EQ(web_chain_links(&C, A1, T - 3600, T, lk, WEB_CHAIN_LINKS, &since), 1);
    WT_EQ(since, T - 300);
    WT_ASSERT(!strcmp(lk[0].lo, A1) && !strcmp(lk[0].hi, B2));
    WT_ASSERT(!strcmp(lk[0].real, B2) && !strcmp(lk[0].twin, A1));
    WT_EQ(lk[0].first_ts, T - 300);
    WT_EQ(lk[0].last_ts, T - 270);
    WT_EQ(lk[0].taint_ts, T - 280);
    WT_EQ(lk[0].attr_ts, T - 290);
    WT_EQ(lk[0].confidence, 70);
    WT_EQ(web_chain_links(&C, B2, T - 3600, T, lk, WEB_CHAIN_LINKS, &since), 1);
    /* Not the pair's: another BSSID, and a window it does not reach. */
    WT_EQ(web_chain_links(&C, "cc:00:00:00:00:03", T - 3600, T, lk, WEB_CHAIN_LINKS, &since), 0);
    WT_EQ(web_chain_links(&C, A1, T - 7200, T - 3600, lk, WEB_CHAIN_LINKS, &since), 0);
    WT_EQ(web_chain_links(&C, A1, T - 260, T, lk, WEB_CHAIN_LINKS, &since), 0);
    /* A string "1" is not sloth's taint, and an out-of-range confidence
     * is absent. */
    web_chain_destroy(&C);
    WT_EQ(web_chain_init(&C), 0);
    episode(T - 100, A1, B2, 0, 0, ",\"confidence\":150");
    char line[256];
    snprintf(line, sizeof(line), "{\"type\":\"twin_episode\",\"ts\":%lld,\"real_bssid\":\"%s\","
             "\"twin_bssid\":\"%s\",\"attack_in_progress\":\"1\",\"attributed\":\"1\"}",
             T - 90, A1, B2);
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_chain_record(&C, &R);
    WT_EQ(web_chain_links(&C, A1, T - 3600, T, lk, WEB_CHAIN_LINKS, &since), 1);
    WT_EQ(lk[0].taint_ts, 0);
    WT_EQ(lk[0].attr_ts, 0);
    WT_EQ(lk[0].confidence, -1);
    /* Refused and counted: an address that is not one, one BSSID twice,
     * no ts. Another type is not this table's at all. */
    episode(T - 80, "aa:00:00:00:00", B2, 1, 1, NULL);
    episode(T - 80, A1, A1, 1, 1, NULL);
    snprintf(line, sizeof(line), "{\"type\":\"twin_episode\",\"real_bssid\":\"%s\","
             "\"twin_bssid\":\"%s\"}", A1, B2);
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_chain_record(&C, &R);
    WT_EQ((long long)C.rejected, 3);
    snprintf(line, sizeof(line), "{\"type\":\"beacon\",\"ts\":%lld,\"real_bssid\":\"%s\","
             "\"twin_bssid\":\"%s\"}", T - 70, A1, "cc:00:00:00:00:03");
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_chain_record(&C, &R);
    WT_EQ(C.n, 1);
    WT_EQ((long long)C.records, 2);
    web_chain_destroy(&C);
}

/* Full: the least recently reported pair makes room, and is counted.
 * Seen red with the eviction picking the first slot (pair 1, reported
 * last, gone in its place). */
static void test_eviction(void) {
    WT_EQ(web_chain_init(&C), 0);
    char a[24], b[24];
    for (int i = 0; i < WEB_CHAIN_PAIRS; i++) {
        snprintf(a, sizeof(a), "aa:00:00:00:01:%02x", i);
        snprintf(b, sizeof(b), "bb:00:00:00:01:%02x", i);
        episode(T - 1000 + i, a, b, 0, 0, NULL);
    }
    /* Pair 0 reported again, newest of all: pair 1 is the oldest now. */
    episode(T - 10, "aa:00:00:00:01:00", "bb:00:00:00:01:00", 0, 0, NULL);
    episode(T - 5, "cc:00:00:00:00:01", "dd:00:00:00:00:01", 0, 0, NULL);
    WT_EQ(C.n, WEB_CHAIN_PAIRS);
    WT_EQ((long long)C.evictions, 1);
    web_chain_pair_t lk[WEB_CHAIN_LINKS];
    long long since;
    WT_EQ(web_chain_links(&C, "aa:00:00:00:01:01", T - 3600, T, lk, WEB_CHAIN_LINKS, &since), 0);
    WT_EQ(web_chain_links(&C, "aa:00:00:00:01:00", T - 3600, T, lk, WEB_CHAIN_LINKS, &since), 1);
    WT_EQ(web_chain_links(&C, "cc:00:00:00:00:01", T - 3600, T, lk, WEB_CHAIN_LINKS, &since), 1);
    web_chain_destroy(&C);
}

/* The ingest feeds it: a twin_episode line through the framer reaches
 * the table set on the feed. Seen red with web_ingest.c's
 * web_chain_record() line taken out. */
static void test_the_feed_reaches_it(void) {
    static web_feed_t f;
    web_live_t live;
    memset(&f, 0, sizeof(f));
    web_feed_reset(&f);
    web_live_init(&live, "unix:/test/sloth.sock");
    WT_EQ(web_chain_init(&C), 0);
    f.chain = &C;
    char line[256];
    snprintf(line, sizeof(line), "{\"type\":\"twin_episode\",\"ts\":%lld,\"real_bssid\":\"%s\","
             "\"twin_bssid\":\"%s\",\"attack_in_progress\":1,\"attributed\":1}\n", T - 60, A1, B2);
    web_feed_bytes(&f, &live, line, strlen(line), 1000);
    WT_EQ((long long)C.records, 1);
    WT_EQ(C.n, 1);
    web_chain_destroy(&C);
    web_live_destroy(&live);
}

static web_rollup_t ru;
static web_tsdb_t   ts;
static web_m4_t     m4;
static web_health_t H;

static void mem_up(void) {
    char err[64];
    WT_EQ(web_rollup_init(&ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, NULL, 30, 256, NULL, NULL), 0);
    WT_EQ(web_chain_init(&C), 0);
    memset(&m4, 0, sizeof(m4));
    m4.tsdb = &ts;
    m4.chain = &C;
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.tsdb = &ts;
    H.m4 = &m4;
}

static void mem_down(void) {
    web_chain_destroy(&C);
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
}

/* The route without sloth.db: the deauth rows as /api/wifi/deauth has
 * them, every sloth.db stage empty and said ("db":"none"), the links
 * from the stream with when they start; one BSSID by bssid=, answered
 * with no deauth key of its own; the parameters checked whole; nothing
 * under Local. The links seen red with web_chain_links() given the
 * window's end as its start (none). The one-BSSID answer seen red with
 * the bssid branch removed (the deauth key listed in its place, which
 * the absence of A1's row then caught). */
static void test_route_without_sloth_db(void) {
    mem_up();
    for (int i = 0; i < 3; i++)
        web_rollup_add(&ru, WM_WIFI_DEAUTH, A1, 10, T - 1200 + i * 10);
    episode(T - 1190, B2, A1, 1, 1, ",\"confidence\":70");
    char q[200];
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=60", T - 3600, T);
    WT_EQ(route(&H, "/api/wifi/chain", q), 200);
    const char *b = body_of(g_out);
    char want[512];
    WT_HAS(b, "{\"metric\":\"wifi.deauth\",\"kind\":\"counter\",");
    snprintf(want, sizeof(want), "\"db\":\"none\",\"links_from\":\"stream\",\"links_since\":%lld,"
             "\"total_keys\":1,\"bssids\":[{\"bssid\":\"" A1 "\",\"total\":30,", T - 1190);
    WT_HAS(b, want);
    WT_HAS(b, "\"floods\":[],\"floods_more\":false,\"twin\":[],\"karma\":[],\"stages_more\":false,"
              "\"assoc\":[0,");
    WT_HAS(b, "\"assoc_n\":0,\"assoc_more\":false,");
    snprintf(want, sizeof(want), "\"links\":[{\"real\":\"" B2 "\",\"twin\":\"" A1 "\",\"first\":%lld,"
             "\"last\":%lld,\"tainted\":%lld,\"attributed\":%lld,\"confidence\":70}],"
             "\"read\":true,\"stages\":1}],\"shown\":1,\"more\":false}",
             T - 1190, T - 1190, T - 1190, T - 1190);
    WT_HAS(b, want);
    /* One BSSID: B2 has no deauth key, and is answered. */
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=60&bssid=BB:00:00:00:00:02", T - 3600, T);
    WT_EQ(route(&H, "/api/wifi/chain", q), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"total_keys\":1,\"bssids\":[{\"bssid\":\"" B2 "\",\"total\":0,\"cells\":[null,");
    WT_HAS(b, "\"tainted\":");
    WT_LACKS(b, "{\"bssid\":\"" A1 "\"");
    WT_HAS(b, "\"stages\":0}],\"shown\":1,\"more\":false}");
    /* Refusals, each with its reason word. */
    static const char *const bad[][2] = {
        { "bssid=aa:00:00:00:00", "bad_bssid" }, { "bssid=", "empty_value" },
        { "cols=0", "bad_cols" }, { "from=x", "bad_from" }, { "q=1", "unknown_parameter" },
        { "bssid=" A1 "&bssid=" B2, "repeated_parameter" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int s = route(&H, "/api/wifi/chain", bad[i][0]);
        snprintf(want, sizeof(want), "{\"error\":\"%s\"", bad[i][1]);
        if (s != 400 || !strstr(body_of(g_out), want))
            fprintf(stderr, "    %s -> %d %s\n", bad[i][0], s, body_of(g_out));
        WT_EQ(s, 400);
        WT_HAS(body_of(g_out), want);
    }
    /* The monitor radio's: nothing under Local, the query still checked. */
    snprintf(q, sizeof(q), "scope=local&from=%lld&to=%lld", T - 3600, T);
    WT_EQ(route(&H, "/api/wifi/chain", q), 200);
    WT_HAS(body_of(g_out), "\"out_of_scope\":true");
    WT_LACKS(body_of(g_out), A1);
    WT_EQ(route(&H, "/api/wifi/chain", "scope=local&bssid=x"), 400);
    /* No table attached: no links, and said. */
    m4.chain = NULL;
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=60", T - 3600, T);
    WT_EQ(route(&H, "/api/wifi/chain", q), 200);
    WT_HAS(body_of(g_out), "\"links_from\":null,\"links_since\":null,");
    WT_HAS(body_of(g_out), "\"links\":[],");
    m4.chain = &C;
    mem_down();
}

#ifndef WITH_SQLITE

void run_chain_tests(void) {
    WT_RUN(test_pairs);
    WT_RUN(test_eviction);
    WT_RUN(test_the_feed_reaches_it);
    WT_RUN(test_route_without_sloth_db);
}

#else

static char g_dir[TEST_TMP_MAX];
static char g_db[128];
static web_slothdb_t sdb;

/* The stages against A1, matched on the alert's key and the
 * association's bssid, none of which a body names: a DEAUTH_FLOOD on
 * it, an EVIL_TWIN pair naming it, a KARMA_AP on it, two associations
 * to it in the window and one before; and rows that are not its: the
 * attack-chain row (its key names the SSID, not a BSSID), another
 * pair's EVIL_TWIN, an association to another BSSID. */
static int seed(void) {
    char sql[4096];
    int n = snprintf(sql, sizeof(sql),
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,technique,"
        "match_ip,match_port,count) VALUES"
        " ('deauth:11:22:33:44:55:66@" A1 "',%lld,%lld,%d,1,'DEAUTH_FLOOD','victim','T1498.001',"
        "NULL,NULL,9),"
        " ('twin:" A1 ":" B2 "::WPA2',%lld,%lld,%d,2,'EVIL_TWIN','Cafe','T1557',NULL,NULL,40),"
        " ('karma:" A1 "',%lld,%lld,%d,1,'KARMA_AP','x','T1557',NULL,NULL,3),"
        " ('twin-chain:Cafe:00112233aabbccdd',%lld,%lld,%d,2,'EVIL_TWIN','Cafe','T1557',"
        "NULL,NULL,5),"
        " ('twin:cc:00:00:00:00:03:dd:00:00:00:00:04::WPA2',%lld,%lld,%d,2,'EVIL_TWIN','x','T1557',"
        "NULL,NULL,1),"
        " ('twin-chain:" E5 ":0011223344556677',%lld,%lld,%d,2,'EVIL_TWIN','x','T1557',"
        "NULL,NULL,1);"
        "INSERT INTO assocs (bssid,sta_mac,ssid,first_seen,last_seen) VALUES"
        " ('" A1 "','11:22:33:44:55:66','Cafe',%lld,%lld),"
        " ('" A1 "','11:22:33:44:55:77','Cafe',%lld,%lld),"
        " ('" A1 "','11:22:33:44:55:88','Cafe',%lld,%lld),"
        " ('cc:00:00:00:00:03','11:22:33:44:55:99','Cafe',%lld,%lld),"
        " ('" E5 "','11:22:33:44:55:aa','Cafe',%lld,%lld);",
        T - 1200, T - 1100, WEB_ALERT_DEAUTH_FLOOD,
        T - 1150, T - 600, WEB_ALERT_EVIL_TWIN,
        T - 900, T - 800, WEB_ALERT_KARMA_AP,
        T - 1150, T - 1000, WEB_ALERT_EVIL_TWIN,
        T - 1150, T - 1000, WEB_ALERT_EVIL_TWIN,
        T - 1150, T - 1000, WEB_ALERT_EVIL_TWIN,
        T - 1000, T - 900, T - 990, T - 900, T - 90000, T - 900, T - 1000, T - 900,
        T - 1000, T - 900);
    if (n < 0 || (size_t)n >= sizeof(sql)) return -1;
    return sdb_exec(g_db, sql);
}

/* Every stage of A1 from sloth.db, each list taking its own type (seen
 * red with emit_stage()'s type test taken out: the KARMA_AP row in the
 * twin list too), the pair matched by the BSSID in its key and the
 * other pair's not (seen red with web_sdb_chain_stages() matching any
 * row of the two types); the associations counted per cell, the one
 * before the window not (held twice, by the statement's first_seen >=
 * ?2 and by take_assoc()'s column test: seen red with both dropped,
 * assoc_n 3); four stages. No key in the body: the key is in the WHERE
 * alone and a stage is numbers (emit_stage()), so no single change puts
 * it there; seen red with the statement selecting it and emit_stage()
 * writing it, together. The station and the SSID are not read at all
 * (the association statement names first_seen alone), so no change to
 * this route short of new code writing them can reach a body: held
 * here against that code, never seen red. */
static void test_route_with_sloth_db(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-chain-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, db_schema_version(), 0), 0);
    WT_EQ(seed(), 0);
    web_slothdb_init(&sdb, g_db, NULL);
    mem_up();
    m4.sdb = &sdb;
    for (int i = 0; i < 3; i++)
        web_rollup_add(&ru, WM_WIFI_DEAUTH, A1, 10, T - 1200 + i * 10);
    episode(T - 1100, B2, A1, 1, 1, ",\"confidence\":70");
    char q[200], want[512];
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=60", T - 3600, T);
    WT_EQ(route(&H, "/api/wifi/chain", q), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"db\":\"open\",");
    snprintf(want, sizeof(want), "\"floods\":[[%lld,%lld,1,9]],\"floods_more\":false,"
             "\"twin\":[[%lld,%lld,2,40]],\"karma\":[[%lld,%lld,1,3]],\"stages_more\":false,",
             T - 1200, T - 1100, T - 1150, T - 600, T - 900, T - 800);
    WT_HAS(b, want);
    /* 60 cells of 60 s from T - 3600: T - 1000 and T - 990 are cell 43. */
    const char *a = strstr(b, "\"assoc\":[");
    WT_ASSERT(a != NULL);
    if (a) {
        a += strlen("\"assoc\":[");
        int c = 0;
        for (int i = 0; i < 43 && a; i++) { a = strchr(a, ','); if (a) a++; }
        if (a) c = atoi(a);
        WT_EQ(c, 2);
    }
    WT_HAS(b, "\"assoc_n\":2,\"assoc_more\":false,");
    WT_HAS(b, "\"read\":true,\"stages\":4}");
    WT_LACKS(b, "deauth:");
    WT_LACKS(b, "twin:");
    WT_LACKS(b, "twin-chain");
    WT_LACKS(b, "karma:");
    WT_LACKS(b, "11:22:33:44:55");
    WT_LACKS(b, "Cafe");
    WT_LACKS(b, "victim");
    /* The other pair's half has its own twin row and nothing else. */
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=60&bssid=cc:00:00:00:00:03", T - 3600, T);
    WT_EQ(route(&H, "/api/wifi/chain", q), 200);
    b = body_of(g_out);
    snprintf(want, sizeof(want), "\"twin\":[[%lld,%lld,2,1]],\"karma\":[],", T - 1150, T - 1000);
    WT_HAS(b, want);
    WT_HAS(b, "\"assoc_n\":1,");
    WT_HAS(b, "\"links\":[],\"read\":true,\"stages\":2}");
    /* A key names a BSSID at its fields only. 00:00:03:dd:00:00 is the
     * text across that pair's two halves ("...00:00:03:dd:00:00..."),
     * and E5 is the SSID-shaped head of an attack-chain key: neither is
     * the pair's nor the chain's (each seen red with the EVIL_TWIN key
     * matched by instr() anywhere in it). KARMA_AP's key is held to its
     * field the same way, but there instr() cannot differ: "karma:" and
     * one MAC hold no other 17 characters shaped like one, so that half
     * provably cannot be seen red and is not claimed. */
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=60&bssid=00:00:03:dd:00:00", T - 3600, T);
    WT_EQ(route(&H, "/api/wifi/chain", q), 200);
    WT_HAS(body_of(g_out), "\"twin\":[],\"karma\":[],");
    /* An ordinary AP: deauth frames (a client leaving is one) and
     * stations associating to it are not two stages of an attack, so it
     * is the rug's, not a chain (seen red with an association counted
     * as a stage whatever else the BSSID has: 2). An association is a
     * stage of the chain on a BSSID sloth has accused or caught luring,
     * as cc:..:03's above. */
    for (int i = 0; i < 3; i++)
        web_rollup_add(&ru, WM_WIFI_DEAUTH, E5, 2, T - 1200 + i * 10);
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=60&bssid=" E5, T - 3600, T);
    WT_EQ(route(&H, "/api/wifi/chain", q), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"twin\":[],\"karma\":[],");
    WT_HAS(b, "\"assoc_n\":1,");
    WT_HAS(b, "\"stages\":1}");
    /* #195: a BSSID with an EVIL_TWIN row and no deauth key is a
     * candidate (cc:..:03, the other pair's half), and every BSSID an
     * alert names reads before the deauth-only ones: A1 (deauth and
     * alerts) first, then cc:..:03, then E5 (deauth alone). The BSSIDs
     * are beacon_aps', so dd:..:04, the pair's other half with no
     * beacon row, is not one. Seen red with the ap_attacks read taken
     * out (cc:..:03 absent, total_keys 2), and with the move to the
     * front taken out (E5 before cc:..:03). */
    WT_EQ(sdb_exec(g_db, "INSERT INTO beacon_aps (bssid,ssid,first_seen,last_seen) VALUES"
                         " ('" A1 "','Cafe',1,1), ('cc:00:00:00:00:03','Cafe',1,1),"
                         " ('" E5 "','Cafe',1,1);"), 0);
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=60", T - 3600, T);
    WT_EQ(route(&H, "/api/wifi/chain", q), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"total_keys\":3,");
    const char *pa = strstr(b, "{\"bssid\":\"" A1 "\"");
    const char *pc = strstr(b, "{\"bssid\":\"cc:00:00:00:00:03\"");
    const char *pe = strstr(b, "{\"bssid\":\"" E5 "\"");
    WT_ASSERT(pa && pc && pe && pa < pc && pc < pe);
    WT_LACKS(b, "dd:00:00:00:00:04");
    mem_down();
    web_slothdb_destroy(&sdb);
    unlink(g_db);
    rmdir(g_dir);
}

void run_chain_tests(void) {
    WT_RUN(test_pairs);
    WT_RUN(test_eviction);
    WT_RUN(test_the_feed_reaches_it);
    WT_RUN(test_route_without_sloth_db);
    WT_RUN(test_route_with_sloth_db);
}

#endif
