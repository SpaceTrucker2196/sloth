/* The Probes view (owner request 2026-11-11; web_probes.h):
 * /api/probes/{clients,ssids,shared,groups} through the route table
 * over a sloth.db generated from sloth's own DDL (sdb_gen.c) on the
 * pinned clock, the similarity's formula on a set worked by hand, the
 * reads on a large file inside the request's budget, and the page's
 * half (web/ui/probes.js) pinned by whole functions.
 *
 * Absence assertions, each seen red under the named mutation and
 * restored: the comments over test_probe_clients(),
 * test_shared_similarity() and test_page_probes() name them. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_assets.h"
#include "web_probes.h"
#include "web_routes.h"
#include "web_scope.h"
#include "web_store.h"
#include "web_tsdb.h"
#include "web_own.h"
#include "web_jsonl.h"
#include "wtest.h"
#include "wt_tmp.h"

#define T SDB_NOW
#define DY 86400LL

static char g_out[131072];

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static int route(const web_health_t *h, const char *path, const char *query) {
    web_req_t *rq = calloc(1, sizeof(*rq));
    web_resp_t r;
    if (!rq) return -1;
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query);
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    int rc = web_route(rq, h, 1, g_out, sizeof(g_out), &r);
    free(rq);
    if (rc != 0) return -1;
    g_out[r.out_len] = '\0';
    return r.status;
}

static int count(const char *s, const char *needle) {
    int n = 0;
    for (const char *h = strstr(s, needle); h; h = strstr(h + 1, needle)) n++;
    return n;
}

/* The formula's two functions, to the figures the header states. */
static void test_weight_and_cut(void) {
    WT_EQ(web_probe_u(0), 2);
    WT_EQ(web_probe_u(39), 2);
    WT_EQ(web_probe_u(60), 3);
    WT_EQ(web_probe_u(319), 15);
    WT_EQ(web_probe_u(320), 16);
    WT_EQ(web_probe_u(1000000), 16);
    WT_ASSERT(fabs(web_probe_weight(6, 2) - 1.0986122886681098) < 1e-12);
    WT_ASSERT(fabs(web_probe_weight(6, 1) - 1.791759469228055) < 1e-12);
    WT_ASSERT(web_probe_weight(6, 6) == 0);       /* everyone asks: no weight */
    WT_ASSERT(web_probe_weight(6, 9) == 0);
    WT_ASSERT(web_probe_weight(0, 0) == 0);
}

#ifndef WITH_SQLITE

/* Without SQLite there is no sloth.db: each route says so. */
static void test_routes_without_sqlite(void) {
    web_health_t H;
    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.m4 = &m4;
    static const char *const P[] = { "/api/probes/clients", "/api/probes/ssids",
                                     "/api/probes/shared", "/api/probes/groups" };
    for (size_t i = 0; i < sizeof(P) / sizeof(P[0]); i++) {
        WT_EQ(route(&H, P[i], ""), 503);
        WT_HAS(body_of(g_out), "{\"error\":\"no_sloth_db\"");
    }
}

#else


static char g_dir[TEST_TMP_MAX];
static char g_db[128];
static web_rollup_t ru;
static web_tsdb_t ts;
static web_slothdb_t sdb;
static web_m4_t m4;
static web_health_t H;

static void db_up(int seed) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-probes-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    char e2[64];
    WT_EQ(web_rollup_init(&ru, 64, 1, e2, sizeof(e2)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, NULL, 30, 256, NULL, NULL), 0);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, db_schema_version(), 0), 0);
    if (seed) WT_EQ(sdb_seed(g_db), 0);
    web_slothdb_init(&sdb, g_db, NULL);
    memset(&m4, 0, sizeof(m4));
    m4.tsdb = &ts;
    m4.sdb = &sdb;
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.tsdb = &ts;
    H.m4 = &m4;
}

static void db_down(void) {
    web_slothdb_destroy(&sdb);
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    unlink(g_db);
    rmdir(g_dir);
}

/* The stations heard probing: the scenario's (probe_clients and
 * pnl_clients, two names), one that sent only wildcard probes, one
 * outside a day's window; what each is tied to.
 *
 * The absences, each seen red under its mutation and restored:
 *   - a wildcard probe is never an SSID, even from a row no sloth
 *     writes: the `AND ssid <> ''` of the row's SSID read removed (the
 *     wildcard-only station listed {"ssid":null), and the
 *     `AND s.ssid <> ''` of the SSIDs statement removed (a null row,
 *     and four networks where three were);
 *   - Local hears none of it: route_m5()'s branch narrowed to
 *     `which == M5_SSID` (each Local answer carried its rows). */
static void test_probe_clients(void) {
    db_up(1);
    static char sql[4096];
    snprintf(sql, sizeof(sql),
        "INSERT INTO probe_clients (mac,ssid,signal_dbm,channel,frame_count,presence,"
        "first_seen,last_seen) VALUES"
        " ('3e:00:00:00:00:05','',-70,11,7,0,%lld,%lld),"
        " ('00:03:93:00:00:03','OldNet',-80,1,2,0,%lld,%lld);"
        "INSERT INTO pnl_clients (mac,mac_random,probe_count,os_fp,phy,first_seen,last_seen)"
        " VALUES ('00:03:93:00:00:03',0,2,'Apple','Wi-Fi 6',%lld,%lld);"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) VALUES"
        " ('00:03:93:00:00:03','OldNet',%lld,%lld),"
        /* A row no sloth writes: an empty name is not a network. */
        " ('3e:00:00:00:00:05','',%lld,%lld);"
        "INSERT INTO seqnum_correlations (mac_a,mac_b,mac_a_random,mac_b_random,gap,dt_ms,"
        "a_count,b_count,first_seen,last_seen) VALUES"
        " ('3e:00:00:00:00:05','da:a1:19:00:00:01',1,1,3,120,4,5,%lld,%lld);",
        T - 3600, T - 30, T - 9 * DY, T - 5 * DY, T - 9 * DY, T - 5 * DY,
        T - 9 * DY, T - 5 * DY, T - 3600, T - 30, T - 900, T - 800);
    WT_EQ(sdb_exec(g_db, sql), 0);
    web_rollup_add(&ru, WM_DEV_PRESENT, "da:a1:19:00:00:01", 1, T - 30);
    WT_EQ(route(&H, "/api/probes/clients", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"now\":1792627200,\"days\":30,\"sort\":\"last\",\"limit\":50,\"offset\":0,");
    WT_HAS(b, "\"seq_read\":true,\"rows\":[{\"mac\":\"3e:00:00:00:00:05\",\"random\":true,"
              "\"vendor\":null,\"frames\":7,\"directed\":null,\"signal\":-70,\"channel\":11,"
              "\"os\":null,\"phy\":null,\"first_seen\":1792623600,\"last_seen\":1792627170,"
              "\"ssid_count\":0,\"ssids\":[],\"ssids_more\":false,\"device\":true,\"assoc\":null,"
              "\"siblings\":[{\"mac\":\"da:a1:19:00:00:01\",\"random\":true,\"vendor\":null,"
              "\"gap\":3,\"dt_ms\":120,\"frames\":9,\"first_seen\":1792626300,"
              "\"last_seen\":1792626400}],\"siblings_total\":1,"
              "\"presence\":\"000000000000000000000000000000000000\"}");
    WT_HAS(b, "{\"mac\":\"da:a1:19:00:00:01\",\"random\":true,\"vendor\":null,\"frames\":10,"
              "\"directed\":3,\"signal\":-48,\"channel\":6,\"os\":null,\"phy\":null,");
    WT_HAS(b, "\"ssid_count\":2,\"ssids\":[{\"ssid\":\"HomeNet\",\"ssid_k\":");
    WT_HAS(b, "{\"ssid\":\"CafeFree\",\"ssid_k\":");
    WT_HAS(b, "\"ssids_more\":false,\"device\":true,\"assoc\":{\"bssid\":\"aa:bb:cc:dd:ee:ff\","
              "\"ssid\":\"HomeNet\",");
    WT_HAS(b, "\"siblings\":[{\"mac\":\"3e:00:00:00:00:05\",");
    WT_HAS(b, "\"presence\":\"000000000000000000000000000000000002\"}");
    WT_HAS(b, "{\"mac\":\"00:03:93:00:00:03\",\"random\":false,\"vendor\":null,\"frames\":2,"
              "\"directed\":2,\"signal\":-80,\"channel\":1,\"os\":\"Apple\",\"phy\":\"Wi-Fi 6\",");
    WT_HAS(b, "],\"count\":3,\"total\":3,\"more\":false,\"next_offset\":null}\n");
    /* Never an SSID: the wildcard's empty name, here or in the count. */
    WT_LACKS(b, "{\"ssid\":null");
    WT_LACKS(b, "{\"ssid\":\"\"");
    /* A day's window leaves the old one out; everything keeps it. */
    WT_EQ(route(&H, "/api/probes/clients", "days=1"), 200);
    WT_HAS(body_of(g_out), "\"count\":2,\"total\":2,");
    WT_LACKS(body_of(g_out), "00:03:93:00:00:03");
    WT_EQ(route(&H, "/api/probes/clients", "days=0"), 200);
    WT_HAS(body_of(g_out), "\"days\":0,");
    WT_HAS(body_of(g_out), "\"count\":3,\"total\":3,");
    /* Orders and a page: N of M. */
    WT_EQ(route(&H, "/api/probes/clients", "sort=ssids&limit=1"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"rows\":[{\"mac\":\"da:a1:19:00:00:01\",");
    WT_HAS(b, "\"count\":1,\"total\":3,\"more\":true,\"next_offset\":1}");
    WT_EQ(route(&H, "/api/probes/clients", "sort=mac&limit=1&offset=2"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[{\"mac\":\"da:a1:19:00:00:01\",");
    WT_EQ(route(&H, "/api/probes/clients", "sort=signal&limit=1"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[{\"mac\":\"da:a1:19:00:00:01\",");
    WT_EQ(route(&H, "/api/probes/clients", "sort=frames&limit=1"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[{\"mac\":\"da:a1:19:00:00:01\",");
    WT_EQ(route(&H, "/api/probes/clients", "sort=first&limit=1"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[{\"mac\":\"da:a1:19:00:00:01\",");
    static const char *const bad[][2] = {
        { "sort=new", "bad_sort" }, { "sort=m.mac", "bad_sort" }, { "limit=0", "bad_limit" },
        { "limit=101", "bad_limit" }, { "offset=x", "bad_offset" }, { "days=401", "bad_days" },
        { "days=x", "bad_days" }, { "q=1", "unknown_parameter" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char want[64];
        WT_EQ(route(&H, "/api/probes/clients", bad[i][0]), 400);
        snprintf(want, sizeof(want), "{\"error\":\"%s\"}", bad[i][1]);
        WT_HAS(body_of(g_out), want);
    }

    /* Monitor's and Hybrid's; Local hears none of it, and a bad
     * parameter is still refused there. */
    WT_EQ(route(&H, "/api/probes/clients", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "{\"scope\":\"monitor\",\"now\":");
    WT_HAS(body_of(g_out), "\"count\":3,\"total\":3,");
    static const char *const P[] = { "/api/probes/clients", "/api/probes/ssids",
                                     "/api/probes/shared", "/api/probes/groups" };
    static const char *const Q[] = { "scope=local", "scope=local",
                                     "mac=da:a1:19:00:00:01&scope=local", "scope=local" };
    for (size_t i = 0; i < sizeof(P) / sizeof(P[0]); i++) {
        WT_EQ(route(&H, P[i], Q[i]), 200);
        WT_HAS(body_of(g_out), "{\"scope\":\"local\",\"out_of_scope\":true,\"reason\":\"an SSID");
        WT_LACKS(body_of(g_out), "da:a1:19:00:00:01");
        WT_LACKS(body_of(g_out), "HomeNet");
    }
    WT_EQ(route(&H, "/api/probes/clients", "sort=new&scope=local"), 400);

    /* The names asked for: how many stations and how many of those MACs
     * randomised, whether an AP beacons it. */
    WT_EQ(sdb_exec(g_db,
        "INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,first_seen,last_seen) VALUES"
        " ('0a:00:00:00:00:01','HomeNet',-50,6,1,2), ('0a:00:00:00:00:02','HomeNet',-41,6,1,2);"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) VALUES"
        " ('00:03:93:00:00:03','HomeNet',1792620000,1792627000);"), 0);
    WT_EQ(route(&H, "/api/probes/ssids", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"now\":1792627200,\"days\":30,\"sort\":\"clients\",\"limit\":50,\"offset\":0,");
    WT_HAS(b, "\"clients\":2,\"u\":2,\"rows\":[{\"ssid\":\"HomeNet\",\"ssid_k\":");
    WT_HAS(b, "\"ssid_np\":false,\"clients\":2,\"random\":1,\"first_seen\":1791763200,"
              "\"last_seen\":1792627000,\"aps\":2,\"ap_signal\":-41,\"uncommon\":true,"
              "\"designated\":null}");
    WT_HAS(b, "{\"ssid\":\"CafeFree\",");
    WT_HAS(b, "\"clients\":1,\"random\":1,");
    WT_HAS(b, "\"aps\":0,\"ap_signal\":null,\"uncommon\":false,\"designated\":null}");
    /* OldNet was last asked for five days ago: in 30 d, not in 1. */
    WT_HAS(b, "{\"ssid\":\"OldNet\",");
    WT_HAS(b, "],\"designated_count\":null,\"count\":3,\"total\":3,\"more\":false,\"next_offset\":null}\n");
    WT_LACKS(b, "{\"ssid\":null");
    /* With sloth's `ownership` record (web_own.h) the network it
     * designates and is being asked for is marked yours, the others
     * not; with none, every row says null above, never false. Seen red
     * with web_probes_ssids_route()'s designated member written as
     * null again. */
    {
        static web_own_t own;
        WT_EQ(web_own_init(&own), 0);
        web_own_bind(&own);
        web_jrec_t rec;
        static const char OWN[] = "{\"type\":\"ownership\",\"ts\":1,\"ssids\":1,"
                                  "\"ssid_0\":\"HomeNet\",\"bssids\":0,\"known_macs\":0}";
        WT_EQ(web_jl_parse(OWN, strlen(OWN), &rec), WEB_JL_OK);
        web_own_record(&own, &rec, 1);
        WT_EQ(route(&H, "/api/probes/ssids", ""), 200);
        b = body_of(g_out);
        WT_HAS(b, "\"aps\":2,\"ap_signal\":-41,\"uncommon\":true,\"designated\":true}");
        WT_HAS(b, "\"aps\":0,\"ap_signal\":null,\"uncommon\":false,\"designated\":false}");
        WT_HAS(b, "],\"designated_count\":1,\"count\":3,");
        WT_LACKS(b, "\"designated\":null");
        web_own_bind(NULL);
        web_own_destroy(&own);
    }
    WT_EQ(route(&H, "/api/probes/ssids", "days=3&sort=ssid&limit=1"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"rows\":[{\"ssid\":\"CafeFree\",");
    WT_HAS(b, "\"count\":1,\"total\":2,\"more\":true,\"next_offset\":1}");
    WT_EQ(route(&H, "/api/probes/ssids", "sort=aps"), 400);
    WT_EQ(route(&H, "/api/probes/ssids", "sort=first&limit=1"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[{\"ssid\":\"HomeNet\",");
    WT_EQ(route(&H, "/api/probes/ssids", "sort=last&limit=1"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[{\"ssid\":\"HomeNet\",");
    WT_EQ(route(&H, "/api/probes/ssids", "sort=df"), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"bad_sort\"}");
    db_down();
}

/* The similarity on a set worked by hand. Six stations, N = 6, U = 2:
 *   common  all six      df 6  w 0
 *   homeA   c1 c2        df 2  w ln 3 = 1.0986
 *   homeB   c1 c2        df 2  w ln 3
 *   work    c1 c3        df 2  w ln 3
 *   solo1   c1           df 1  w ln 6 = 1.7918
 *   solo2   c2           df 1  w ln 6
 * c1 against c2: shared homeA and homeB (and common, weighing nothing),
 * 2 ln 3 = 2.1972 over (3 ln 3 + ln 6) + (2 ln 3 + ln 6) - 2 ln 3 =
 * 6.8794, 0.319. c1 against c3: one uncommon name shared, so nothing at
 * the minimum of 2; at 1, ln 3 over 3 ln 3 + ln 6 = 5.0876, 0.216. c4,
 * c5 and c6 ask only for what everyone asks for: never a candidate.
 *
 * The absences, each seen red under its mutation and restored:
 *   - a pair under the minimum is not ranked: `if (cs[k].shared_u < min)
 *     continue;` made `< 0` (c3 listed at the minimum of 2);
 *   - a name everyone asks for makes no candidate and no group:
 *     uncommon() made `df >= 2` alone (c4, c5 and c6 listed, "common"
 *     among a group's names);
 *   - and weighs nothing: web_probe_weight() made a constant 1 (c2's
 *     0.319 and c3's 0.216 gone, the three weights with them). */
static void sim_seed(void) {
    static char sql[4096];
    size_t o = 0;
    static const char *const ROWS[][2] = {
        { "1", "common" }, { "2", "common" }, { "3", "common" }, { "4", "common" },
        { "5", "common" }, { "6", "common" }, { "1", "homeA" }, { "2", "homeA" },
        { "1", "homeB" }, { "2", "homeB" }, { "1", "work" }, { "3", "work" },
        { "1", "solo1" }, { "2", "solo2" },
    };
    o += (size_t)snprintf(sql + o, sizeof(sql) - o,
                          "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) VALUES");
    for (size_t i = 0; i < sizeof(ROWS) / sizeof(ROWS[0]); i++)
        o += (size_t)snprintf(sql + o, sizeof(sql) - o, "%s ('c2:00:00:00:00:0%s','%s',%lld,%lld)",
                              i ? "," : "", ROWS[i][0], ROWS[i][1], T - DY, T - 60 - (long long)i);
    o += (size_t)snprintf(sql + o, sizeof(sql) - o,
                          "; INSERT INTO pnl_clients (mac,mac_random,probe_count,first_seen,"
                          "last_seen) VALUES");
    for (int i = 1; i <= 6; i++)
        o += (size_t)snprintf(sql + o, sizeof(sql) - o, "%s ('c2:00:00:00:00:0%d',1,3,%lld,%lld)",
                              i > 1 ? "," : "", i, T - DY, T - 60);
    snprintf(sql + o, sizeof(sql) - o, ";");
    WT_EQ(sdb_exec(g_db, sql), 0);
}

static void test_shared_similarity(void) {
    db_up(0);
    sim_seed();
    WT_EQ(route(&H, "/api/probes/shared", "mac=c2:00:00:00:00:01"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"mac\":\"c2:00:00:00:00:01\",\"now\":1792627200,\"days\":30,\"n_clients\":6,"
              "\"u\":2,\"min\":2,\"formula\":\"w(s) = ln(N / df(s)); sim = sum of w over the "
              "shared SSIDs / sum of w over either's; uncommon: 2 <= df <= U\",\"ssids\":[");
    WT_HAS(b, "{\"ssid\":\"common\",\"ssid_k\":");
    WT_HAS(b, "\"ssid_np\":false,\"df\":6,\"w\":0.000,\"uncommon\":false}");
    WT_HAS(b, "\"df\":2,\"w\":1.099,\"uncommon\":true}");
    WT_HAS(b, "\"df\":1,\"w\":1.792,\"uncommon\":false}");
    WT_HAS(b, "],\"ssids_more\":false,\"rows\":[{\"mac\":\"c2:00:00:00:00:02\",\"random\":true,"
              "\"vendor\":null,\"sim\":0.319,\"shared_uncommon\":2,\"shared_n\":3,"
              "\"ssid_count\":4,\"ssids_more\":false,\"shared\":[{\"ssid\":\"homeA\",");
    WT_HAS(b, "],\"count\":1,\"total\":1,\"capped\":false}\n");
    WT_LACKS(b, "c2:00:00:00:00:03");
    WT_LACKS(b, "c2:00:00:00:00:04");
    /* At a minimum of one: c3 too, ranked under c2; still nobody who
     * shares only the common name. */
    WT_EQ(route(&H, "/api/probes/shared", "mac=c2:00:00:00:00:01&min=1"), 200);
    b = body_of(g_out);
    const char *r2 = strstr(b, "{\"mac\":\"c2:00:00:00:00:02\""), *r3 = strstr(b, "{\"mac\":\"c2:00:00:00:00:03\"");
    WT_ASSERT(r2 && r3 && r2 < r3);
    WT_HAS(b, "{\"mac\":\"c2:00:00:00:00:03\",\"random\":true,\"vendor\":null,\"sim\":0.216,"
              "\"shared_uncommon\":1,\"shared_n\":2,\"ssid_count\":2,");
    WT_HAS(b, "],\"count\":2,\"total\":2,\"capped\":false}\n");
    WT_LACKS(b, "c2:00:00:00:00:04");
    WT_LACKS(b, "c2:00:00:00:00:05");
    WT_LACKS(b, "c2:00:00:00:00:06");
    /* Symmetric: c2's answer names c1 at the same figure. */
    WT_EQ(route(&H, "/api/probes/shared", "mac=c2:00:00:00:00:02"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[{\"mac\":\"c2:00:00:00:00:01\",\"random\":true,"
                           "\"vendor\":null,\"sim\":0.319,");
    /* A station that asks for nothing by name, and one sloth.db does
     * not hold: an empty answer. */
    WT_EQ(route(&H, "/api/probes/shared", "mac=c2-00-00-00-00-04"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[],\"count\":0,\"total\":0,\"capped\":false}");
    WT_EQ(route(&H, "/api/probes/shared", "mac=02:99:99:99:99:99"), 200);
    WT_HAS(body_of(g_out), "\"ssids\":[],\"ssids_more\":false,\"rows\":[],\"count\":0,");
    static const char *const bad[][2] = {
        { "", "missing_mac" }, { "mac=nope", "bad_mac" }, { "mac=c2:00:00:00:00:01&min=0", "bad_min" },
        { "mac=c2:00:00:00:00:01&min=9", "bad_min" }, { "mac=c2:00:00:00:00:01&days=999", "bad_days" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char want[64];
        WT_EQ(route(&H, "/api/probes/shared", bad[i][0]), 400);
        snprintf(want, sizeof(want), "{\"error\":\"%s\"}", bad[i][1]);
        WT_HAS(body_of(g_out), want);
    }

    /* The groups: at 2, c1 and c2 on homeA and homeB; at 1, c3 joins
     * through work. Never the three that share only the common name. */
    WT_EQ(route(&H, "/api/probes/groups", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"now\":1792627200,\"days\":30,\"n_clients\":6,\"u\":2,\"min\":2,");
    WT_HAS(b, "\"ssids_uncommon\":3,\"ssids_read\":3,\"capped\":false,\"groups\":[{\"clients\":2,"
              "\"ssids\":2,\"macs\":[{\"mac\":\"c2:00:00:00:00:01\",\"random\":true,\"vendor\":null},"
              "{\"mac\":\"c2:00:00:00:00:02\",\"random\":true,\"vendor\":null}],\"names\":["
              "{\"ssid\":\"homeA\",");
    WT_HAS(b, "\"df\":2,\"in_group\":2},{\"ssid\":\"homeB\",");
    WT_HAS(b, "],\"count\":1,\"total\":1}\n");
    WT_LACKS(b, "c2:00:00:00:00:03");
    WT_EQ(route(&H, "/api/probes/groups", "min=1"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"groups\":[{\"clients\":3,\"ssids\":3,\"macs\":[{\"mac\":\"c2:00:00:00:00:01\",");
    WT_HAS(b, "{\"mac\":\"c2:00:00:00:00:03\",");
    WT_HAS(b, "{\"ssid\":\"work\",");
    WT_LACKS(b, "c2:00:00:00:00:04");
    WT_LACKS(b, "\"common\"");
    WT_EQ(route(&H, "/api/probes/groups", "min=0"), 400);
    WT_EQ(route(&H, "/api/probes/groups", "mac=c2:00:00:00:00:01"), 400);
    /* A window with nobody in it. */
    WT_EQ(sdb_exec(g_db, "UPDATE pnl_ssids SET last_seen = 1000;"
                         "UPDATE pnl_clients SET last_seen = 1000;"), 0);
    WT_EQ(route(&H, "/api/probes/groups", "days=1"), 200);
    WT_HAS(body_of(g_out), "\"n_clients\":0,\"u\":2,\"min\":2,");
    WT_HAS(body_of(g_out), "\"groups\":[],\"count\":0,\"total\":0}");
    db_down();
}

static long long mono_ms_t(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

#define BIG_CLIENTS 50000
#define BIG_ALERTS  600000

/* A sloth.db of the size the History view's large-file test builds
 * (test_history.c big_db(): 600,000 alert episodes, a twentieth of them
 * in the last 30 days) with 50,000 probing stations beside them: four
 * named SSIDs each (200,000 pnl_ssids rows), one every station asks
 * for, one ten ask for, two that two ask for; a probe_clients and a
 * pnl_clients row each; an AP for a tenth of the ten-station names. */
static int big_probe_db(const char *path) {
    static char sql[6000];
    if (sdb_make(path, db_schema_version(), 0) != 0) return -1;
    snprintf(sql, sizeof(sql),
        "BEGIN;"
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < %d - 1)"
        " INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,count)"
        " SELECT 'g:' || i, f, f + i %% 900, i %% 90, i %% 3, 'PORT_SCAN', 1 FROM"
        " (SELECT i, CASE WHEN i < %d THEN %lld + (i * 37) %% %lld"
        "  ELSE %lld + (i * 37) %% %lld END AS f FROM n);"
        "CREATE TEMP TABLE c AS WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n"
        " WHERE i < %d - 1) SELECT i, printf('02:00:%%02x:%%02x:%%02x:%%02x', i / 16777216 %% 256,"
        " i / 65536 %% 256, i / 256 %% 256, i %% 256) AS mac, %lld - (i * 53) %% %lld AS l FROM n;"
        "INSERT INTO probe_clients (mac,ssid,signal_dbm,channel,frame_count,presence,first_seen,"
        "last_seen) SELECT mac, 'home-' || (i / 2), -40 - i %% 50, 1 + i %% 11, 5 + i %% 90, 0,"
        " l - 3600, l FROM c;"
        "INSERT INTO pnl_clients (mac,mac_random,probe_count,first_seen,last_seen)"
        " SELECT mac, 1, 4 + i %% 9, l - 3600, l FROM c;"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) SELECT mac, 'carrier', l - 3600, l FROM c;"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen)"
        " SELECT mac, 'net-' || (i %% 5000), l - 3600, l FROM c;"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen)"
        " SELECT mac, 'home-' || (i / 2), l - 3600, l FROM c;"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen)"
        " SELECT mac, 'chain-' || (i %% 25000), l - 3600, l FROM c;"
        "INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,first_seen,last_seen)"
        " SELECT printf('0a:00:00:00:%%02x:%%02x', i / 256, i %% 256), 'net-' || (i * 10), -60, 6,"
        " l - 3600, l FROM c WHERE i < 500;"
        "INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,first_seen,last_seen)"
        " SELECT printf('0a:00:00:01:%%02x:%%02x', i / 256, i %% 256), 'carrier', -70, 11,"
        " l - 3600, l FROM c WHERE i < 40;"
        "INSERT INTO assocs (bssid,sta_mac,ssid,first_seen,last_seen)"
        " SELECT '0a:00:00:01:00:00', mac, 'carrier', l - 3600, l FROM c WHERE i < 5000;"
        "INSERT INTO seqnum_correlations (mac_a,mac_b,gap,dt_ms,a_count,b_count,first_seen,last_seen)"
        " SELECT a.mac, b.mac, 2, 90, 3, 3, a.l - 60, a.l FROM c a JOIN c b ON b.i = a.i + 1"
        " WHERE a.i %% 2 = 0 AND a.i < 30000;"
        "COMMIT;",
        BIG_ALERTS, BIG_ALERTS - BIG_ALERTS / 20,
        T - 400 * DY, 369 * DY, T - 30 * DY + 1000, 30 * DY - 2000,
        BIG_CLIENTS, T - 60, 20 * DY);
    return sdb_exec(path, sql);
}

/* One route on the large file: 200 inside the request's budget (scaled
 * under the sanitizers, as every timed read is), its time printed. */
static const char *timed(const char *path, const char *query) {
    long long t0 = mono_ms_t();
    int st = route(&H, path, query);
    long long ms = mono_ms_t() - t0;
    fprintf(stderr, "    %s?%s: %lld ms, %zu bytes (budget %d)\n", path, query, ms,
            strlen(body_of(g_out)), WEB_SDB_HTTP_MS);
    WT_EQ(st, 200);
    WT_ASSERT(ms < (long long)WEB_SDB_HTTP_MS * web_sdb_test_budget_scale);
    return body_of(g_out);
}

static void test_large_file_inside_the_budget(void) {
    db_up(0);
    long long t0 = mono_ms_t();
    unlink(g_db);
    WT_EQ(big_probe_db(g_db), 0);
    fprintf(stderr, "    generated %d alerts, %d probing stations, %d pnl_ssids rows in %lld ms\n",
            BIG_ALERTS, BIG_CLIENTS, BIG_CLIENTS * 4, mono_ms_t() - t0);
    const char *b = timed("/api/probes/clients", "");
    WT_HAS(b, "\"count\":50,\"total\":50000,\"more\":true,\"next_offset\":50}");
    b = timed("/api/probes/clients", "sort=ssids&limit=100&days=0");
    WT_HAS(b, "\"total\":50000,\"more\":true,");
    WT_HAS(b, "\"ssid_count\":4,");
    /* 15,000 correlations: every one read, each row's own found. */
    WT_HAS(b, "\"seq_read\":true,");
    WT_HAS(b, "\"siblings_total\":1,");
    /* 1 + 5000 + 25000 + 25000 names. */
    b = timed("/api/probes/ssids", "");
    WT_HAS(b, "\"clients\":50000,\"u\":16,\"rows\":[{\"ssid\":\"carrier\",");
    WT_HAS(b, "\"clients\":50000,\"random\":50000,");
    WT_HAS(b, "\"aps\":40,\"ap_signal\":-70,\"uncommon\":false,");
    WT_HAS(b, "\"count\":50,\"total\":55001,\"more\":true,\"next_offset\":50}");
    b = timed("/api/probes/ssids", "sort=last&limit=100");
    WT_HAS(b, "\"total\":55001,");
    /* Station 0: carrier (50,000), net-0 (10), home-0 (2), chain-0 (2).
     * Station 25000 shares chain-0 and net-0; station 1 home-0 alone and
     * eight more net-0 alone, so they rank only at a minimum of one. */
    b = timed("/api/probes/shared", "mac=02:00:00:00:00:00&days=0");
    WT_HAS(b, "\"n_clients\":50000,\"u\":16,\"min\":2,");
    WT_HAS(b, "\"ssid\":\"carrier\",");
    WT_HAS(b, "\"df\":50000,\"w\":0.000,\"uncommon\":false}");
    WT_HAS(b, "\"count\":1,\"total\":1,\"capped\":false}");
    WT_HAS(b, "\"rows\":[{\"mac\":\"02:00:00:00:61:a8\",");
    b = timed("/api/probes/shared", "mac=02:00:00:00:00:00&days=0&min=1");
    WT_HAS(b, "\"count\":10,\"total\":10,\"capped\":false}");
    WT_HAS(b, "{\"mac\":\"02:00:00:00:00:01\",");
    /* The groups meet their caps on this file and say so: 55,000
     * uncommon names seen, WEB_PROBE_G_SSIDS of them read. */
    b = timed("/api/probes/groups", "days=0");
    WT_HAS(b, "\"n_clients\":50000,\"u\":16,\"min\":2,\"formula\":");
    WT_HAS(b, "\"ssids_uncommon\":55000,");
    WT_HAS(b, "\"capped\":true,");
    WT_ASSERT(count(b, "{\"clients\":") <= WEB_PROBE_G_SHOWN);
    WT_ASSERT(count(b, "{\"clients\":") > 0);
    db_down();
}

#endif

/* ── the page ────────────────────────────────────────────────────────── */

/* web/ui/probes.js, its functions whole where the wording or the order
 * matters. */
static const char JS_TIED[] =
    "  function tied(cell, d) {\n"
    "    var any = false;\n"
    "    if (d.device) {\n"
    "      var b = H.el(\"button\", \"lk\", \"device\");\n"
    "      b.type = \"button\";\n"
    "      b.title = \"sloth.db holds a devices row for this MAC: its drawer\";\n"
    "      b.addEventListener(\"click\", function (e) { e.stopPropagation(); H.openDrawer(String(d.mac)); });\n"
    "      cell.appendChild(b);\n"
    "      any = true;\n"
    "    }\n"
    "    if (d.assoc) {\n"
    "      if (any) cell.appendChild(document.createTextNode(\"; \"));\n"
    "      cell.appendChild(H.el(\"span\", \"d-dim\", \"associated to \"));\n"
    "      cell.appendChild(macBtn(d.assoc.bssid, false, \"an association sloth saw for this MAC: the access \" +\n"
    "                              \"point's drawer\", H.openDrawer));\n"
    "      if (d.assoc.ssid !== null) {\n"
    "        cell.appendChild(document.createTextNode(\" \"));\n"
    "        cell.appendChild(H.ssidSpan(String(d.assoc.ssid), d.assoc.ssid_k, d.assoc.ssid_np));\n"
    "      }\n"
    "      any = true;\n"
    "    }\n"
    "    (d.siblings || []).forEach(function (s) {\n"
    "      if (any) cell.appendChild(document.createTextNode(\"; \"));\n"
    "      cell.appendChild(H.el(\"span\", \"d-dim\", \"may be one radio with \"));\n"
    "      cell.appendChild(macBtn(s.mac, s.random, \"sloth's sequence-number correlation (gap \" + s.gap + \", \" +\n"
    "                              s.dt_ms + \" ms apart, \" + s.frames + \" frames): the two MACs' 802.11 counters \" +\n"
    "                              \"ran on from one another. Consistent with one radio; a hypothesis a passive \" +\n"
    "                              \"sensor corroborates and never confirms. Click: this MAC's shared networks\",\n"
    "                              select));\n"
    "      any = true;\n"
    "    });\n"
    "    if (d.siblings_total > (d.siblings || []).length)\n"
    "      cell.appendChild(H.el(\"span\", \"d-dim\", \" +\" + (d.siblings_total - d.siblings.length) + \" more\"));\n"
    "    if (!any) cell.appendChild(H.el(\"span\", \"d-dim\", \"-\"));\n"
    "  }\n"
    "";

static const char JS_FORMULA[] =
    "  function formula(j) {\n"
    "    return \"sim = sum of w over the networks both ask for / sum of w over the networks either asks for, \" +\n"
    "           \"w = ln(N / stations asking), N = \" + j.n_clients + \"; uncommon: asked for by 2 to \" + j.u +\n"
    "           \" stations; at least \" + j.min + \" shared uncommon\";\n"
    "  }\n"
    "";

static const char JS_SELECT[] =
    "  function select(mac) {\n"
    "    P.sel = mac;\n"
    "    var gen = ++P.sgen, d = days();\n"
    "    if (DTC) clientsDraw();\n"
    "    $(\"pr-sh-cap\").textContent = \"loading\";\n"
    "    H.getJSON(\"/api/probes/shared?mac=\" + encodeURIComponent(mac) + \"&days=\" + d + \"&min=\" + minShared())\n"
    "      .then(function (j) {\n"
    "        if (gen !== P.sgen || j.out_of_scope) return;\n"
    "        sharedDraw(j, d);\n"
    "      }).catch(function (e) {\n"
    "        if (gen !== P.sgen) return;\n"
    "        clear(\"pr-sh\");\n"
    "        $(\"pr-sh-cap\").textContent = H.errText(e.message);\n"
    "      });\n"
    "  }\n"
    "";

static const char JS_SHOW[] =
    "  function show() {\n"
    "    if (!H) return;\n"
    "    var gen = ++P.gen;\n"
    "    // Under Local the view's empty state says why; nothing is asked.\n"
    "    if (H.scope() === \"local\") return;\n"
    "    tables();\n"
    "    clientsLoad(gen, false);\n"
    "    ssidsLoad(gen);\n"
    "    groupsLoad(gen);\n"
    "    if (P.sel) select(P.sel);\n"
    "    else {\n"
    "      clear(\"pr-sh\");\n"
    "      $(\"pr-sh-cap\").textContent = \"pick a station above: the stations asking for the same uncommon networks\";\n"
    "    }\n"
    "  }\n"
    "";

/* The tab: in the bar, the views, the address and the scope switch as
 * the Radar tab is; its four panels and their captions; what a row is
 * tied to, each with its basis and the correlation in hypothesis words;
 * the formula as the caption says it; the WiFi view's clients panel
 * pointing here. The wording is "probe for the same networks": the page
 * never says "same owner" (seen red with that phrase put into the
 * panel's sub line), and a wildcard-only station's row says so rather
 * than list a name (seen red with the row's else branch removed: an
 * empty cell). */
static void test_page_probes(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, JS_TIED);
    WT_HAS(p, JS_FORMULA);
    WT_HAS(p, JS_SELECT);
    WT_HAS(p, JS_SHOW);
    WT_HAS(p, "               \"lookup\", \"tacdb\", \"ble\", \"gnss\", \"adsb\", \"aprs\", \"radar\", \"fleet\"];\n"
              "  // The Probes view (web/ui/probes.js), a tab of its own.\n"
              "  VIEWS.push(\"probes\");\n");
    WT_HAS(p, "    if (v === \"probes\" && window.SlothProbes) SlothProbes.show();\n");
    WT_HAS(p, "  $(\"nav-probes\").addEventListener(\"click\", function () { show(\"probes\"); });\n");
    WT_HAS(p, "    $(\"v-probes\").classList.toggle(\"scoped-out\", SCOPE === \"local\");\n");
    WT_HAS(p, "      <li><button type=\"button\" class=\"go\" id=\"nav-probes\">Probes</button></li>\n");
    WT_HAS(p, "<section class=\"panel scope-empty\" id=\"pr-scope-empty\"><div class=\"label\">Probes</div>"
              "<p>Nothing here under Local. Probe requests are the passive monitor radio's;");
    WT_HAS(p, "<button type=\"button\" class=\"dt-reset\" id=\"w-probes-go\">the Probes tab</button>");
    WT_HAS(p, "    $(\"w-probes-go\").addEventListener(\"click\", function () { H.show(\"probes\"); });");
    /* Its four controls kept through the page's one door, each put back
     * only as one of its own options. */
    WT_HAS(p, "      var c = $(id), v = H.prefGet(\"probes.\" + id);\n"
              "      for (var i = 0; typeof v === \"string\" && i < c.options.length; i++)\n"
              "        if (c.options[i].value === v) c.value = v;\n");
    WT_HAS(p, "        H.prefSet(\"probes.\" + id, c.value);\n");
    static const char *const IDS[] = {
        "v-probes", "nav-probes", "pr-days", "pr-min", "pr-cl-sort", "pr-cl-more", "pr-cl-box",
        "pr-cl-head", "pr-cl", "pr-cl-cap", "pr-cl-tools", "pr-sh", "pr-sh-cap", "pr-ss-sort",
        "pr-ss-box", "pr-ss-head", "pr-ss", "pr-ss-cap", "pr-ss-tools", "pr-gr", "pr-gr-cap",
        "w-probes-go",
    };
    for (size_t i = 0; i < sizeof(IDS) / sizeof(IDS[0]); i++) {
        char want[64];
        snprintf(want, sizeof(want), " id=\"%s\"", IDS[i]);
        WT_EQ(count(p, want), 1);
    }
    /* The four fetches, each with the window; the two tables are the
     * page's one table implementation. */
    WT_HAS(p, "H.getJSON(\"/api/probes/clients?days=\" + d + \"&sort=\" + encodeURIComponent(sort) + "
              "\"&limit=\" + PAGE +");
    WT_HAS(p, "var path = \"/api/probes/ssids?days=\" + d + \"&sort=\" + encodeURIComponent(sort) + "
              "\"&limit=100\" +\n               H.fvQuery(\"probes\");");
    WT_HAS(p, "    H.getJSON(path)\n");
    WT_HAS(p, "H.getJSON(\"/api/probes/groups?days=\" + d + \"&min=\" + minShared()).then(");
    WT_HAS(p, "DTC = H.DataTable({ id: \"prclients\", label: \"stations heard probing\",");
    WT_HAS(p, "DTS = H.DataTable({ id: \"prssids\", label: \"networks asked for\",");
    /* N of M when a page is not the whole. */
    WT_HAS(p, ": n < P.total ? n + \" of \" + P.total + \" stations, \" + SORTS[sort]");
    WT_HAS(p, ": n < j.total ? n + \" of \" + j.total + \" networks, \" + SS_SORTS[sort] : \"\" }) +\n"
              "          (fw ? \"; \" + fw : \"\");");
    WT_HAS(p, "state: (n < j.total ? n + \" of \" + j.total + \" stations, the most similar\" : \"\") +");
    WT_HAS(p, "(j.capped ? \"; capped: \" + j.ssids_read + \" of \" + j.ssids_uncommon + "
              "\" uncommon networks read\" : \"\") });");
    /* The empty states, in words. */
    WT_HAS(p, "state: !n ? \"no station heard probing in the window\"");
    WT_HAS(p, "state: !n ? \"no network asked for by name in the window\"");
    WT_HAS(p, "\"none: no other station asks for \" + j.min + \" of its uncommon networks\"");
    WT_HAS(p, "(!n ? \"no group in the window\" :");
    WT_HAS(p, "      else ss.appendChild(H.el(\"span\", \"d-dim\", \"wildcard probes only: no network named\"));\n");
    /* The wording. */
    WT_HAS(p, "<div class=\"label\">probing for the same networks</div>");
    WT_HAS(p, "\" stations probe for \" + g.ssids +");
    WT_LACKS(p, "same owner");
    WT_LACKS(p, "same person");
    WT_LACKS(p, "same user");
    /* The privacy note, where the view begins. */
    WT_HAS(p, "A list of the networks a device asks for can name a home or a workplace: this view "
              "shows what sloth.db already holds and exports nothing of its own.");
    const char *scss = strstr(p, ".ssidgo { cursor: pointer;"), *pcss = strstr(p, ".prrow, .prsrow { font-size: 12px;");
    const char *sjs = strstr(p, "// slothweb: one SSID's detail"), *pjs = strstr(p, "// slothweb: the Probes view");
    const char *ini = strstr(p, "window.SlothProbes) SlothProbes.init(");
    WT_ASSERT(scss && pcss && scss < pcss);
    WT_ASSERT(sjs && pjs && ini && ini < sjs && sjs < pjs);
}

void run_probes_tests(void) {
    WT_RUN(test_weight_and_cut);
#ifndef WITH_SQLITE
    WT_RUN(test_routes_without_sqlite);
#else
    WT_RUN(test_probe_clients);
    WT_RUN(test_shared_similarity);
    WT_RUN(test_large_file_inside_the_budget);
#endif
    WT_RUN(test_page_probes);
}
