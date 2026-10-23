/* The WiFi routes (#163, M5; web_wifi.h) through the route table,
 * without a socket: the channel waterfall and the deauth timeline over
 * slothweb's rollup and store, the AP table over a sloth.db generated
 * from sloth's own DDL (sdb_gen.c), on the pinned clock SDB_NOW; and
 * the page's WiFi view, its elements and its fetches. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_assets.h"
#include "web_routes.h"
#include "web_series.h"
#include "web_store.h"
#include "web_tsdb.h"
#include "web_wifi.h"
#include "wtest.h"

#define T SDB_NOW

static char g_out[65536];

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

/* The cells of key in a channels body, comma-joined, into out. */
static int cells_of(const char *b, const char *member, const char *key,
                    char *out, size_t cap) {
    char want[96];
    snprintf(want, sizeof(want), "{\"%s\":\"%s\"", member, key);
    const char *p = strstr(b, want);
    const char *c = p ? strstr(p, "\"cells\":[") : NULL;
    const char *e = c ? strchr(c, ']') : NULL;
    out[0] = '\0';
    if (!e) return -1;
    c += 9;
    snprintf(out, cap, "%.*s", (int)(e - c), c);
    return 0;
}

/* The n-th (0-based) comma-separated item of list. */
static void item(const char *list, int n, char *out, size_t cap) {
    const char *p = list;
    for (int i = 0; i < n && p; i++) {
        p = strchr(p, ',');
        if (p) p++;
    }
    out[0] = '\0';
    if (!p) return;
    const char *e = strchr(p, ',');
    snprintf(out, cap, "%.*s", e ? (int)(e - p) : (int)strlen(p), p);
}

static web_rollup_t ru;
static web_tsdb_t   ts;
static web_m4_t     m4;
static web_health_t H;

static void mem_up(void) {
    char err[64];
    WT_EQ(web_rollup_init(&ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, NULL, 30, 256, NULL, NULL), 0);
    memset(&m4, 0, sizeof(m4));
    m4.tsdb = &ts;
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.tsdb = &ts;
    H.m4 = &m4;
}

static void mem_down(void) {
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
}

/* Bands in order with their channels by number, a gauge's cell the
 * mean of its buckets, a counter's their sum, an empty cell null. The
 * band order seen red with by_band() comparing the key text alone (11
 * before 6). */
static void test_channels_grid(void) {
    mem_up();
    web_rollup_add(&ru, WM_WIFI_AP_COUNT, "1", 2, T - 3600);
    web_rollup_add(&ru, WM_WIFI_AP_COUNT, "1", 4, T - 3590);
    web_rollup_add(&ru, WM_WIFI_AP_COUNT, "11", 9, T - 1200);
    web_rollup_add(&ru, WM_WIFI_AP_COUNT, "6", 7, T - 40);
    web_rollup_add(&ru, WM_WIFI_AP_COUNT, "6", 8, T - 39);   /* one bucket: 7.5 */
    web_rollup_add(&ru, WM_WIFI_AP_COUNT, "36", 1.5, T - 1800);
    web_rollup_add(&ru, WM_WIFI_AP_COUNT, "6g37", 3, T - 1790);
    web_rollup_add(&ru, WM_WIFI_CTRL_TOTAL, "6", 5, T - 100);
    web_rollup_add(&ru, WM_WIFI_CTRL_TOTAL, "6", 7, T - 95);
    web_rollup_add(&ru, WM_WIFI_CTRL_TOTAL, "6", 1, T - 80);
    char q[160];
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=90", T - 3600, T);
    WT_EQ(route(&H, "/api/wifi/channels", q), 200);
    const char *b = body_of(g_out);
    char want[256];
    snprintf(want, sizeof(want), "{\"metric\":\"wifi.ap_count\",\"kind\":\"gauge\","
             "\"unit\":\"APs\",\"tier\":\"fine\",\"step\":10,\"from\":%lld,\"to\":%lld,"
             "\"cols\":90,\"col_s\":40,\"total_keys\":5,\"channels\":[", T - 3600, T);
    WT_HAS(b, want);
    const char *k1 = strstr(b, "{\"key\":\"1\",\"band\":\"2.4\"");
    const char *k6 = strstr(b, "{\"key\":\"6\",\"band\":\"2.4\"");
    const char *k11 = strstr(b, "{\"key\":\"11\",\"band\":\"2.4\"");
    const char *k36 = strstr(b, "{\"key\":\"36\",\"band\":\"5\"");
    const char *k37 = strstr(b, "{\"key\":\"6g37\",\"band\":\"6\"");
    WT_ASSERT(k1 && k6 && k11 && k36 && k37);
    WT_ASSERT(k1 < k6 && k6 < k11 && k11 < k36 && k36 < k37);
    char cells[2048], v[32];
    WT_EQ(cells_of(b, "key", "1", cells, sizeof(cells)), 0);
    item(cells, 0, v, sizeof(v)); WT_ASSERT(!strcmp(v, "3"));
    item(cells, 1, v, sizeof(v)); WT_ASSERT(!strcmp(v, "null"));
    item(cells, 89, v, sizeof(v)); WT_ASSERT(!strcmp(v, "null"));
    item(cells, 90, v, sizeof(v)); WT_ASSERT(!strcmp(v, ""));      /* 90 cells */
    WT_EQ(cells_of(b, "key", "6", cells, sizeof(cells)), 0);
    item(cells, 89, v, sizeof(v)); WT_ASSERT(!strcmp(v, "7.5"));
    WT_EQ(cells_of(b, "key", "36", cells, sizeof(cells)), 0);
    item(cells, 45, v, sizeof(v)); WT_ASSERT(!strcmp(v, "1.5"));
    WT_HAS(b, "\"shown\":5,\"more\":false}");
    /* The counter: the cell is the sum of its buckets. */
    snprintf(q, sizeof(q), "metric=ctrl_total&from=%lld&to=%lld&cols=90", T - 3600, T);
    WT_EQ(route(&H, "/api/wifi/channels", q), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"metric\":\"wifi.ctrl_total\",\"kind\":\"counter\"");
    WT_EQ(cells_of(b, "key", "6", cells, sizeof(cells)), 0);
    item(cells, 87, v, sizeof(v)); WT_ASSERT(!strcmp(v, "12"));
    item(cells, 88, v, sizeof(v)); WT_ASSERT(!strcmp(v, "1"));
    /* The defaults: the last hour, 96 columns. */
    WT_EQ(route(&H, "/api/wifi/channels", ""), 200);
    WT_HAS(body_of(g_out), "\"cols\":90,\"col_s\":40,");   /* 3600 / 96 rounds up to 40 */
    mem_down();
}

/* Past WEB_WIFI_ROWS channels the answer says "more"; each refusal is a
 * 400 with its word and never the value (seen red with the deauth route
 * passing the from value as the error's detail). */
static void test_channels_bounds_and_refusals(void) {
    mem_up();
    for (int ch = 1; ch <= 45; ch++) {
        char k[8];
        snprintf(k, sizeof(k), "%d", ch);
        web_rollup_add(&ru, WM_WIFI_AP_COUNT, k, 1, T - 60);
    }
    WT_EQ(route(&H, "/api/wifi/channels", ""), 200);
    WT_HAS(body_of(g_out), "\"total_keys\":45,");
    WT_HAS(body_of(g_out), "\"shown\":40,\"more\":true}");
    char q[160];
    static const char *const bad[][2] = {
        { "metric=xyz", "unknown_metric" }, { "cols=0", "bad_cols" },
        { "cols=97", "bad_cols" }, { "cols=1x", "bad_cols" },
        { "from=1792627200&to=1792627200", "empty_range" },
        { "to=1792727200", "to_in_future" }, { "from=x", "bad_from" },
        { "from=1&to=1792627200", "range_too_long" }, { "bogus=1", "unknown_parameter" },
        { "cols=4&cols=5", "repeated_parameter" },
        { "from=1792540000&to=1792540600", "tier_unavailable" },   /* > 24 h ago, no store */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        WT_EQ(route(&H, "/api/wifi/channels", bad[i][0]), 400);
        snprintf(q, sizeof(q), "{\"error\":\"%s\"}", bad[i][1]);
        WT_HAS(body_of(g_out), q);
        WT_EQ(route(&H, "/api/wifi/deauth",
                    !strncmp(bad[i][0], "metric", 6) ? "metric=ap_count" : bad[i][0]),
              400);
    }
    WT_LACKS(body_of(g_out), "1792540000");
    /* No time series at all. */
    web_health_t h0;
    memset(&h0, 0, sizeof(h0));
    h0.wall_s = T;
    WT_EQ(route(&h0, "/api/wifi/channels", ""), 503);
    WT_HAS(body_of(g_out), "{\"error\":\"no_time_series\"}");
    WT_EQ(route(&h0, "/api/wifi/deauth", ""), 503);
    WT_EQ(route(&h0, "/api/wifi/aps", ""), 503);
    WT_HAS(body_of(g_out), "{\"error\":\"no_sloth_db\"");
    mem_down();
}

/* The page's WiFi view: its elements and the fetches it builds. Seen
 * red with w-heat renamed in index.html. */
static void test_page_carries_the_wifi_view(void) {
    const char *p = (const char *)web_page;
    static const char *const ids[] = {
        "v-wifi", "nav-wifi", "w-metric", "w-win", "w-heat", "w-heat-note",
        "w-aps", "w-aps-count", "w-sort", "w-deauth", "w-da-note", "w-probe",
        "w-pc-note",
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        char want[64], a[64], b[64];
        snprintf(want, sizeof(want), "id=\"%s\"", ids[i]);
        WT_HAS(p, want);
        if (i < 1) continue;                        /* "v-" + view */
        snprintf(a, sizeof(a), "$(\"%s\")", ids[i]);
        snprintf(b, sizeof(b), "set(\"%s\",", ids[i]);
        if (!strstr(p, a) && !strstr(p, b)) fprintf(stderr, "    no lookup of %s\n", ids[i]);
        WT_ASSERT(strstr(p, a) || strstr(p, b));
    }
    WT_HAS(p, "var p = \"/api/wifi/\" + route + \"?from=\" + r.from + \"&to=\" + r.to + \"&cols=96\";");
    WT_HAS(p, "if (metric !== \"\") p += \"&metric=\" + encodeURIComponent(metric);");
    WT_HAS(p, "getJSON(wifiGridPath(\"channels\", metric, r))");
    WT_HAS(p, "getJSON(wifiGridPath(\"deauth\", \"\", r))");
    WT_HAS(p, "getJSON(\"/api/wifi/aps?limit=100&sort=\" + encodeURIComponent(sort))");
    WT_HAS(p, "series(\"wifi.probe_clients\", \"\", tier, r.from, r.to)");
    WT_HAS(p, "baseline(\"wifi.probe_clients\", \"\")");
    WT_HAS(p, "if (e.key === \"5\") show(\"wifi\");");
}

#ifndef WITH_SQLITE

void run_wifi_tests(void) {
    WT_RUN(test_channels_grid);
    WT_RUN(test_channels_bounds_and_refusals);
    WT_RUN(test_page_carries_the_wifi_view);
}

#else

static char g_dir[64];
static char g_db[128];
static web_store_t st;
static web_slothdb_t sdb;

static void db_up(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/slothweb-wifi-XXXXXX");
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    char p[160], err[512], e2[64];
    snprintf(p, sizeof(p), "%s/slothweb.db", g_dir);
    WT_EQ(web_store_open(&st, p, err, sizeof(err)), 0);
    WT_EQ(web_rollup_init(&ru, 64, 1, e2, sizeof(e2)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, &st, 30, 256, NULL, NULL), 0);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, db_schema_version(), 0), 0);
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
    web_store_close(&st);
    const char *files[] = { "sloth.db", "slothweb.db", "slothweb.db-wal",
                            "slothweb.db-shm" };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        char p[192];
        snprintf(p, sizeof(p), "%s/%s", g_dir, files[i]);
        unlink(p);
    }
    rmdir(g_dir);
}

static void qrow(web_qrow_t *r, int tier, int metric, const char *key,
                 long long t, double v) {
    memset(r, 0, sizeof(*r));
    r->tier = tier;
    r->metric = metric;
    snprintf(r->key, sizeof(r->key), "%s", key);
    r->t = t;
    r->sum = r->min = r->max = v;
    r->n = 1;
}

/* A channel only the store holds (the rollup never saw it: a restart)
 * is in the grid, at the tier the range needs. Seen red with
 * grid_keys() reading the rollup's keys alone (no 149). */
static void test_channels_from_the_store(void) {
    db_up();
    web_qrow_t r[4];
    qrow(&r[0], WEB_TIER_MINUTE, WM_WIFI_AP_COUNT, "149", T - 2 * 86400 + 600, 4);
    qrow(&r[1], WEB_TIER_MINUTE, WM_WIFI_AP_COUNT, "149", T - 2 * 86400 + 660, 6);
    qrow(&r[2], WEB_TIER_HOUR, WM_WIFI_AP_COUNT, "1", T - 9 * 86400, 2);
    qrow(&r[3], WEB_TIER_HOUR, WM_WIFI_AP_COUNT, "1", T - 8 * 86400, 2);
    WT_EQ(web_store_write(&st, r, 4), 0);
    char q[160], cells[4096], v[32];
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=24", T - 2 * 86400, T - 86400);
    WT_EQ(route(&H, "/api/wifi/channels", q), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"tier\":\"minute\",\"step\":60,");
    WT_HAS(b, "\"col_s\":3600,");
    WT_EQ(cells_of(b, "key", "149", cells, sizeof(cells)), 0);
    item(cells, 0, v, sizeof(v));
    WT_ASSERT(!strcmp(v, "5"));
    WT_HAS(b, "{\"key\":\"149\",\"band\":\"5\"");
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - 10 * 86400, T);
    WT_EQ(route(&H, "/api/wifi/channels", q), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"tier\":\"hour\",\"step\":3600,");
    WT_HAS(b, "{\"key\":\"1\",\"band\":\"2.4\"");
    WT_LACKS(b, "\"149\"");                  /* minute rows, not hour */
    db_down();
}

/* The deauth timeline: bssids by frames, each with the DEAUTH_FLOOD
 * episodes against it in the range, matched on the alert's key, which
 * no body names. The flood list seen red with web_sdb_deauth_floods()
 * taking any type from DEAUTH_FLOOD's up (the evil-twin row joined it).
 * The key is in the WHERE alone and a flood is numbers (emit_flood()),
 * so no single change puts it in a body; seen red with the statement
 * selecting it and emit_flood() writing it, together. */
static void test_deauth_timeline(void) {
    db_up();
    char sql[2048];
    snprintf(sql, sizeof(sql),
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,"
        "technique,match_ip,match_port,count) VALUES"
        " ('deauth:11:22:33:44:55:66@aa:00:00:00:00:01',%lld,%lld,%d,2,"
        "'DEAUTH_FLOOD','victim=11:22:33:44:55:66 bssid=aa:00:00:00:00:01','T1498.001',"
        "NULL,NULL,9),"
        " ('deauth:11:22:33:44:55:77@aa:00:00:00:00:01',%lld,%lld,%d,1,"
        "'DEAUTH_FLOOD','old','T1498.001',NULL,NULL,4),"
        " ('twin:ff:00:00:00:00:09@aa:00:00:00:00:02',%lld,%lld,3,1,'Evil twin','x','T1557',"
        "NULL,NULL,1);",
        T - 1200, T - 1100, WEB_ALERT_DEAUTH_FLOOD,
        T - 90000, T - 89000, WEB_ALERT_DEAUTH_FLOOD,
        T - 1200, T - 1100);
    WT_EQ(sdb_exec(g_db, sql), 0);
    web_rollup_add(&ru, WM_WIFI_DEAUTH, "aa:00:00:00:00:02", 5, T - 300);
    for (int i = 0; i < 3; i++)
        web_rollup_add(&ru, WM_WIFI_DEAUTH, "aa:00:00:00:00:01", 10, T - 1200 + i * 10);
    char q[160];
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=60", T - 3600, T);
    WT_EQ(route(&H, "/api/wifi/deauth", q), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"metric\":\"wifi.deauth\",\"kind\":\"counter\",");
    WT_HAS(b, "\"db\":\"open\",\"total_keys\":2,\"bssids\":[{\"bssid\":\"aa:00:00:00:00:01\","
              "\"total\":30,");
    char want[160];
    snprintf(want, sizeof(want), "\"floods\":[[%lld,%lld,2,9]],\"floods_more\":false}",
             T - 1200, T - 1100);
    WT_HAS(b, want);
    WT_HAS(b, "{\"bssid\":\"aa:00:00:00:00:02\",\"total\":5,");
    WT_HAS(b, "\"floods\":[],\"floods_more\":false}");
    WT_LACKS(b, "deauth:");
    WT_LACKS(b, "11:22:33:44:55");
    WT_LACKS(b, "victim");
    char cells[2048], v[32];
    WT_EQ(cells_of(b, "bssid", "aa:00:00:00:00:01", cells, sizeof(cells)), 0);
    item(cells, 40, v, sizeof(v));
    WT_ASSERT(!strcmp(v, "30"));
    /* Without sloth.db the frames stand alone. */
    m4.sdb = NULL;
    WT_EQ(route(&H, "/api/wifi/deauth", q), 200);
    WT_HAS(body_of(g_out), "\"db\":\"none\",");
    m4.sdb = &sdb;
    db_down();
}

static const char *ap_row(const char *b, const char *bssid) {
    char want[64];
    snprintf(want, sizeof(want), "{\"bssid\":\"%s\"", bssid);
    return strstr(b, want);
}

/* The AP table: the AKM bits by name, the downgrade flags by name, MFP
 * as a word, the SSID history and its count, the KARMA score where
 * there is one; sorts and paging; a markup SSID escaped (seen red with
 * ap_json() writing the SSID raw). */
static void test_ap_table(void) {
    db_up();
    char sql[4096];
    long long bits = (1LL << 2) | (1LL << 8) | (1LL << 24) | (1LL << 30);
    snprintf(sql, sizeof(sql),
        "INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,enc,akm,mfp,vendor,"
        "has_wps,phy,downgrade_flags,akm_bits,first_seen,last_seen) VALUES"
        " ('0a:00:00:00:00:01','Cafe',-50,6,'WPA3','PSK,SAE',1,'Acme',1,'ax',13,%lld,%lld,%lld),"
        " ('0a:00:00:00:00:02',NULL,NULL,36,'OPEN','',0,NULL,0,NULL,0,0,%lld,%lld),"
        " ('0a:00:00:00:00:03','<script>x</script>',-80,11,'WPA2','PSK',2,NULL,0,"
        "NULL,0,4,%lld,%lld);"
        "INSERT INTO beacon_ap_ssids (bssid,ssid,first_seen,last_seen) VALUES"
        " ('0a:00:00:00:00:01','Cafe',%lld,%lld), ('0a:00:00:00:00:01','FreeWiFi',%lld,%lld),"
        " ('0a:00:00:00:00:01','attwifi',%lld,%lld), ('0a:00:00:00:00:03','<script>x</script>',%lld,%lld);"
        "INSERT INTO karma_candidates (bssid,ssid_count,pnl_overlap,pnl_best,"
        "pnl_jaccard_ppm,ie_uniform,deauth_chain,score,top_ssid,first_seen,last_seen)"
        " VALUES ('0a:00:00:00:00:01',3,2,2,500000,1,1,80,'FreeWiFi',%lld,%lld);",
        bits, T - 86400, T - 60, T - 3600, T - 600, T - 7200, T - 7000,
        T - 86400, T - 60, T - 3000, T - 120, T - 5000, T - 4000, T - 7200, T - 7000,
        T - 3600, T - 60);
    WT_EQ(sdb_exec(g_db, sql), 0);
    WT_EQ(route(&H, "/api/wifi/aps", ""), 200);
    const char *b = body_of(g_out);
    const char *a1 = ap_row(b, "0a:00:00:00:00:01");
    const char *a2 = ap_row(b, "0a:00:00:00:00:02");
    const char *a3 = ap_row(b, "0a:00:00:00:00:03");
    WT_ASSERT(a1 && a2 && a3 && a1 < a2 && a2 < a3);   /* last_seen DESC */
    WT_HAS(a1, "{\"bssid\":\"0a:00:00:00:00:01\",\"ssid\":\"Cafe\",\"signal\":-50,"
               "\"channel\":6,\"enc\":\"WPA3\",\"akm\":\"PSK,SAE\",\"akm_bits\":1090519300,"
               "\"akm_names\":[\"PSK\",\"SAE\",\"SAE-EXT-KEY\",\"AKM-30\"],\"mfp\":1,"
               "\"mfp_word\":\"capable\",\"downgrade\":13,\"downgrade_names\":"
               "[\"SAE/PSK transition\",\"MFP optional\",\"WPA1 alongside RSN\"],"
               "\"vendor\":\"Acme\",\"phy\":\"ax\",\"wps\":true,");
    WT_HAS(a1, "\"ssid_count\":3,\"multi_ssid\":true,\"ssids\":[{\"ssid\":\"Cafe\",");
    WT_HAS(a1, "{\"ssid\":\"attwifi\",");
    WT_HAS(a1, "\"ssids_more\":false,\"karma\":{\"score\":80,\"ssid_count\":3,"
               "\"pnl_overlap\":2,\"ie_uniform\":true}}");
    WT_HAS(a2, "{\"bssid\":\"0a:00:00:00:00:02\",\"ssid\":null,\"signal\":null,"
               "\"channel\":36,\"enc\":\"OPEN\",\"akm\":null,\"akm_bits\":0,"
               "\"akm_names\":[],\"mfp\":0,\"mfp_word\":\"off\",\"downgrade\":0,"
               "\"downgrade_names\":[],");
    WT_HAS(a2, "\"ssid_count\":0,\"multi_ssid\":false,\"ssids\":[],\"ssids_more\":false,"
               "\"karma\":null}");
    WT_HAS(a3, "\"ssid\":\"\\u003cscript\\u003ex\\u003c/script\\u003e\"");
    WT_HAS(a3, "\"mfp_word\":\"required\"");
    WT_LACKS(b, "<script>");
    WT_HAS(b, "\"count\":3,\"more\":false,\"next_offset\":null}");
    /* Sorts and a page. */
    WT_EQ(route(&H, "/api/wifi/aps", "sort=bssid&limit=1&offset=1"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"rows\":[{\"bssid\":\"0a:00:00:00:00:02\"");
    WT_HAS(b, "\"count\":1,\"more\":true,\"next_offset\":2}");
    WT_EQ(route(&H, "/api/wifi/aps", "sort=ssids"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[{\"bssid\":\"0a:00:00:00:00:01\"");
    WT_EQ(route(&H, "/api/wifi/aps", "sort=karma"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[{\"bssid\":\"0a:00:00:00:00:01\"");
    static const char *const bad[][2] = {
        { "sort=new", "bad_sort" }, { "limit=0", "bad_limit" }, { "limit=101", "bad_limit" },
        { "offset=x", "bad_offset" }, { "q=1", "unknown_parameter" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char want[64];
        WT_EQ(route(&H, "/api/wifi/aps", bad[i][0]), 400);
        snprintf(want, sizeof(want), "{\"error\":\"%s\"}", bad[i][1]);
        WT_HAS(body_of(g_out), want);
    }
    db_down();
}

/* The worst row WEB_WIFI_AP_ROW_MAX is sized for fits it: every text at
 * its cut length of characters escaped six-fold, every AKM bit, every
 * downgrade bit, a full SSID history. */
static void test_ap_worst_case_fits(void) {
    db_up();
    char t63[64];
    memset(t63, '<', 63);
    t63[63] = '\0';
    static char sql[16384];
    size_t o = (size_t)snprintf(sql, sizeof(sql),
        "INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,enc,akm,mfp,vendor,"
        "has_wps,phy,downgrade_flags,akm_bits,first_seen,last_seen) VALUES"
        " ('0a:00:00:00:00:09','%s',-50,165,'%s','%s',2,'%s',1,'%s',255,4294967295,"
        "1000000000,9999999999);"
        "INSERT INTO karma_candidates (bssid,ssid_count,pnl_overlap,pnl_best,"
        "pnl_jaccard_ppm,ie_uniform,deauth_chain,score,top_ssid,first_seen,last_seen)"
        " VALUES ('0a:00:00:00:00:09',999999999,999999999,1,1,1,1,999999999,'x',1,1);",
        t63, t63, t63, t63, t63);
    for (int i = 0; i < WEB_WIFI_SSIDS + 1; i++)
        o += (size_t)snprintf(sql + o, sizeof(sql) - o,
            "INSERT INTO beacon_ap_ssids (bssid,ssid,first_seen,last_seen) VALUES"
            " ('0a:00:00:00:00:09','%d%.62s',1000000000,%lld);", i, t63,
            9999999990LL - i);
    WT_EQ(sdb_exec(g_db, sql), 0);
    WT_EQ(route(&H, "/api/wifi/aps", ""), 200);
    const char *b = body_of(g_out);
    const char *s = strstr(b, "\"rows\":[");
    const char *e = s ? strstr(s, "],\"count\":1,") : NULL;
    WT_ASSERT(s && e);
    if (s && e) {
        size_t row = (size_t)(e - s - 8);
        fprintf(stderr, "    worst AP row: %zu bytes of %d\n", row, WEB_WIFI_AP_ROW_MAX);
        WT_ASSERT(row > WEB_WIFI_AP_ROW_MAX * 3 / 4);
        WT_ASSERT(row <= WEB_WIFI_AP_ROW_MAX);
    }
    WT_HAS(b, "\"ssids_more\":true");
    db_down();
}

void run_wifi_tests(void) {
    WT_RUN(test_channels_grid);
    WT_RUN(test_channels_bounds_and_refusals);
    WT_RUN(test_page_carries_the_wifi_view);
    WT_RUN(test_channels_from_the_store);
    WT_RUN(test_deauth_timeline);
    WT_RUN(test_ap_table);
    WT_RUN(test_ap_worst_case_fits);
}

#endif
