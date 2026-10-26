/* The History routes (#163, M5; web_history.h) through the route table,
 * without a socket, over a sloth.db generated from sloth's own DDL
 * (sdb_gen.c) on the pinned clock SDB_NOW: the 30 d strip, who was here
 * with its presence restricted to the range, the alerts and flows in
 * it, the survey sessions, and --report's "new since the previous
 * session" ported, held against both sloth's rules (src/db.c,
 * src/posture.c) and docs/wiki/sqlite-schema.md's own recipe. And the
 * page's History view. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_assets.h"
#include "web_history.h"
#include "web_recipes.h"
#include "web_routes.h"
#include "web_store.h"
#include "web_tsdb.h"
#include "wtest.h"

#define T SDB_NOW
#define HR 3600LL
#define DY 86400LL

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

/* Every History route needs sloth.db. */
static void test_without_sloth_db(void) {
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T;
    static const char *const paths[] = {
        "/api/history/overview", "/api/history/devices", "/api/history/alerts",
        "/api/history/flows", "/api/sessions", "/api/sessions/new",
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        WT_EQ(route(&h, paths[i], ""), 503);
        WT_HAS(body_of(g_out), "{\"error\":\"no_sloth_db\"");
    }
}

/* The page's History view. Seen red with h-strip renamed in index.html,
 * and with the session chip's click handler removed from app.js. */
static void test_page_carries_the_history_view(void) {
    const char *p = (const char *)web_page;
    static const char *const ids[] = {
        "v-history", "nav-history", "h-strip", "h-range", "h-sessions", "h-new",
        "h-new-note", "h-devs", "h-dev-count", "h-alerts", "h-al-count",
        "h-anoms", "h-flows",
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        char want[64], a[64], b[64];
        snprintf(want, sizeof(want), "id=\"%s\"", ids[i]);
        WT_HAS(p, want);
        if (i < 1) continue;
        snprintf(a, sizeof(a), "$(\"%s\")", ids[i]);
        snprintf(b, sizeof(b), "set(\"%s\",", ids[i]);
        if (!strstr(p, a) && !strstr(p, b)) fprintf(stderr, "    no lookup of %s\n", ids[i]);
        WT_ASSERT(strstr(p, a) || strstr(p, b));
    }
    WT_HAS(p, "return \"/api/history/\" + route + \"?from=\" + from + \"&to=\" + to + (extra || \"\");");
    WT_HAS(p, "getJSON(histPath(\"devices\", from, to, \"&limit=200\"))");
    WT_HAS(p, "getJSON(histPath(\"alerts\", from, to, \"&limit=100\"))");
    WT_HAS(p, "getJSON(histPath(\"flows\", from, to, \"&limit=100\"))");
    WT_HAS(p, "getJSON(\"/api/history/overview?from=\" + from + \"&to=\" + to + \"&cols=180\")");
    WT_HAS(p, "getJSON(\"/api/sessions/new?id=\" + encodeURIComponent(String(id)))");
    WT_HAS(p, "getJSON(\"/api/anomalies?since=\" + from)");
    WT_HAS(p, "b.addEventListener(\"click\", function () { newSince(s.id); });");
    WT_HAS(p, "row.addEventListener(\"click\", function () { openDrawer(d.mac); });");
    WT_HAS(p, "if (e.key === \"8\") show(\"history\");");
}

#ifndef WITH_SQLITE

void run_history_tests(void) {
    WT_RUN(test_without_sloth_db);
    WT_RUN(test_page_carries_the_history_view);
}

#else

#include <sqlite3.h>

static char g_dir[64];
static char g_db[128];
static web_store_t st;
static web_rollup_t ru;
static web_tsdb_t ts;
static web_slothdb_t sdb;
static web_m4_t m4;
static web_health_t H;

/* Four visits:
 *   S1 T-10d .. T-9d          the first: no previous, no list
 *   S2 T-5d .. never ended    a crash: its own end is the next start
 *   S3 T-2d .. T-2d+1h        previous S2, which never ended: since S2's start
 *   S4 T-1h .. running        the latest: --report's own window
 * and the entities each one met first. */
static int seed(void) {
    char sql[8192];
    int n = snprintf(sql, sizeof(sql),
        "INSERT INTO sessions (id,started,ended,site_label) VALUES"
        " (1,%lld,%lld,'office'), (2,%lld,NULL,'office'),"
        " (3,%lld,%lld,'lab'), (4,%lld,NULL,'<b>now</b>');"
        "INSERT INTO devices (mac,ip,hostname,vendor,first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:01',NULL,'ancient','Old',%lld,%lld),"
        " ('02:00:00:00:00:02',NULL,'after-s1',NULL,%lld,%lld),"
        " ('02:00:00:00:00:03',NULL,NULL,'Mid',%lld,%lld),"
        " ('02:00:00:00:00:04',NULL,'','Acme',%lld,%lld);"
        "INSERT INTO beacon_aps (bssid,ssid,first_seen,last_seen) VALUES"
        " ('0a:00:00:00:00:01','NewNet',%lld,%lld),"
        " ('0a:00:00:00:00:02','',%lld,%lld);"
        "INSERT INTO probe_clients (mac,ssid,first_seen,last_seen) VALUES"
        " ('06:00:00:00:00:01','',%lld,%lld),"
        " ('06:00:00:00:00:02','HomeNet',%lld,%lld);"
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,"
        "technique,match_ip,match_port,count) VALUES"
        " ('cred:10.0.0.1:10.0.0.9:21:ftp:carol-secret',%lld,%lld,12,1,"
        "'CLEARTEXT_CRED','ftp user carol-secret','T1040','10.0.0.1',21,2),"
        " ('scan:10.0.0.7',%lld,%lld,0,0,'PORT_SCAN','x','T1046','10.0.0.7',NULL,5);"
        "INSERT INTO ssh_flows (src_ip,dst_ip,banner_count,server_banner,first_seen,"
        "last_seen) VALUES ('10.0.0.1','10.0.0.2',3,'SSH-2.0-x',%lld,%lld);"
        "INSERT INTO rdp_flows (src_ip,dst_ip,connect_req_count,last_cookie,"
        "proto_mask,first_seen,last_seen) VALUES ('10.0.0.3','10.0.0.4',2,"
        "'mstshash=dave-secret',1,%lld,%lld);"
        "INSERT INTO smb_sessions (client_ip,server_ip,server_port,dialect,obs_count,"
        "first_seen,last_seen) VALUES ('10.0.0.5','10.0.0.6',445,'SMB1',7,%lld,%lld);"
        "INSERT INTO snmp_flows (src_ip,dst_ip,get_count,getnext_count,set_count,"
        "version,community_count,first_seen,last_seen) VALUES"
        " ('10.0.0.7','10.0.0.8',1,2,3,1,1,%lld,%lld);"
        "INSERT INTO mqtt_flows (src_ip,dst_ip,connect_count,last_username,"
        "first_seen,last_seen) VALUES ('10.0.0.9','10.0.0.10',1,'erin-secret',%lld,%lld);",
        T - 10 * DY, T - 9 * DY, T - 5 * DY, T - 2 * DY, T - 2 * DY + HR, T - HR,
        T - 20 * DY, T - 19 * DY, T - 9 * DY + 100, T - 8 * DY, T - 4 * DY, T - 3 * DY,
        T - 1800, T - 60,
        T - 1800, T - 60, T - 3 * DY, T - 2 * DY,
        T - 1700, T - 60, T - 6 * DY, T - 6 * DY,
        T - 3 * HR, T - 2 * HR, T - 15 * DY, T - 14 * DY,
        T - 2 * HR, T - HR, T - 2 * HR, T - HR, T - 2 * HR, T - HR, T - 2 * HR, T - HR,
        T - 2 * HR, T - HR);
    if (n < 0 || (size_t)n >= sizeof(sql)) return -1;
    return sdb_exec(g_db, sql);
}

static void up(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/slothweb-hist-XXXXXX");
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    char p[160], err[512], e2[64];
    snprintf(p, sizeof(p), "%s/slothweb.db", g_dir);
    WT_EQ(web_store_open(&st, p, err, sizeof(err)), 0);
    WT_EQ(web_rollup_init(&ru, 64, 1, e2, sizeof(e2)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, &st, 30, 256, NULL, NULL), 0);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, db_schema_version(), 0), 0);
    WT_EQ(seed(), 0);
    web_slothdb_init(&sdb, g_db, NULL);
    memset(&m4, 0, sizeof(m4));
    m4.tsdb = &ts;
    m4.sdb = &sdb;
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.tsdb = &ts;
    H.m4 = &m4;
}

static void down(void) {
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

/* The 30 d strip: devices first seen and alerts begun per cell, the
 * sessions in the range as markers. */
static void test_overview(void) {
    char q[160];
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=30", T - 30 * DY, T);
    WT_EQ(route(&H, "/api/history/overview", q), 200);
    const char *b = body_of(g_out);
    char want[256];
    snprintf(want, sizeof(want), "{\"from\":%lld,\"to\":%lld,\"cols\":30,\"cell_s\":86400,"
             "\"devices\":[0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,1,0,0,1],"
             "\"alerts\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1],",
             T - 30 * DY, T);
    WT_HAS(b, want);
    WT_HAS(b, "\"sessions\":[{\"id\":4,");
    WT_HAS(b, "\"label\":\"\\u003cb\\u003enow\\u003c/b\\u003e\"");
    WT_HAS(b, "{\"id\":1,\"started\":");
    WT_HAS(b, "\"sessions_more\":false}");
    /* A range with S1 alone (seen red with the session filter's start
     * bound removed: S3 listed). */
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - 11 * DY, T - 8 * DY);
    WT_EQ(route(&H, "/api/history/overview", q), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"sessions\":[{\"id\":1,");
    WT_LACKS(b, "{\"id\":3,");
    /* A range after S1 ended and before S2 began: no session at all
     * (seen red with the filter's end bound removed: S1 listed). */
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - 8 * DY, T - 6 * DY);
    WT_EQ(route(&H, "/api/history/overview", q), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"sessions\":[],");
    WT_LACKS(b, "{\"id\":1,");
    /* The default: the last 30 days, 180 cells. */
    WT_EQ(route(&H, "/api/history/overview", ""), 200);
    snprintf(want, sizeof(want), "{\"from\":%lld,\"to\":%lld,\"cols\":180,\"cell_s\":14400,",
             T - 30 * DY, T);
    WT_HAS(body_of(g_out), want);
    static const char *const bad[][2] = {
        { "cols=0", "bad_cols" }, { "cols=361", "bad_cols" }, { "from=x", "bad_from" },
        { "to=y", "bad_to" }, { "from=10&to=5", "empty_range" },
        { "from=1&to=1792627200", "range_too_long" }, { "to=1792900000", "to_in_future" },
        { "z=1", "unknown_parameter" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        WT_EQ(route(&H, "/api/history/overview", bad[i][0]), 400);
        snprintf(want, sizeof(want), "{\"error\":\"%s\"}", bad[i][1]);
        WT_HAS(body_of(g_out), want);
        if (strncmp(bad[i][0], "cols", 4)) {
            WT_EQ(route(&H, "/api/history/devices", bad[i][0]), 400);
            WT_EQ(route(&H, "/api/history/alerts", bad[i][0]), 400);
            WT_EQ(route(&H, "/api/history/flows", bad[i][0]), 400);
        }
    }
}

static int has_mac(const char *b, const char *mac) {
    char want[48];
    snprintf(want, sizeof(want), "{\"mac\":\"%s\"", mac);
    return strstr(b, want) != NULL;
}

/* Who was here: [first_seen, last_seen] overlapping [from, to], edges
 * included; the presence strip over the range itself. The edges seen
 * red with the statement's ">=" made ">", and the range ending a second
 * early with its "<= ?2" made "<= ?2 + 1". */
static void test_who_was_here(void) {
    char q[160];
    /* D3 is [T-4d, T-3d]: a range ending at its first second has it,
     * one ending a second before does not. */
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - 5 * DY, T - 4 * DY);
    WT_EQ(route(&H, "/api/history/devices", q), 200);
    WT_ASSERT(has_mac(body_of(g_out), "02:00:00:00:00:03"));
    WT_ASSERT(!has_mac(body_of(g_out), "02:00:00:00:00:04"));
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - 5 * DY, T - 4 * DY - 1);
    WT_EQ(route(&H, "/api/history/devices", q), 200);
    WT_ASSERT(!has_mac(body_of(g_out), "02:00:00:00:00:03"));
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - 3 * DY, T - 2 * DY);
    WT_EQ(route(&H, "/api/history/devices", q), 200);
    WT_ASSERT(has_mac(body_of(g_out), "02:00:00:00:00:03"));   /* its last second */
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - 3 * DY + 1, T - 2 * DY);
    WT_EQ(route(&H, "/api/history/devices", q), 200);
    WT_ASSERT(!has_mac(body_of(g_out), "02:00:00:00:00:03"));
    /* Presence over the range: an hour, 144 cells of 60 s (none finer
     * than the minute tier); a fine bucket at T-1000 sets cell 43. */
    web_rollup_add(&ru, WM_DEV_PRESENT, "02:00:00:00:00:04", 1, T - 1000);
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - HR, T);
    WT_EQ(route(&H, "/api/history/devices", q), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"presence_cell_s\":60,\"presence_cells\":60,\"presence_tier\":\"minute\",");
    const char *row = strstr(b, "{\"mac\":\"02:00:00:00:00:04\"");
    WT_ASSERT(row != NULL);
    char hx[64] = "\"presence\":\"";
    size_t hl = strlen(hx);
    for (int d = 0; d < 36; d++) hx[hl++] = d == 10 ? '1' : '0';
    hx[hl++] = '"';
    hx[hl] = '\0';
    WT_HAS(row, hx);
    /* Paging. */
    snprintf(q, sizeof(q), "from=%lld&to=%lld&limit=1", T - 30 * DY, T);
    WT_EQ(route(&H, "/api/history/devices", q), 200);
    WT_HAS(body_of(g_out), "\"count\":1,\"more\":true,\"next_offset\":1}");
    WT_EQ(route(&H, "/api/history/devices", "limit=0"), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"bad_limit\"}");
}

/* hex: 36 digits, cell c set for each c in cells (n of them), as
 * web_dev_presence_hex() writes them. */
static void strip_hex(const int *cells, int n, char *out) {
    int v[36] = { 0 };
    for (int i = 0; i < n; i++) v[cells[i] / 4] |= 8 >> (cells[i] % 4);
    int o = sprintf(out, "\"presence\":\"");
    for (int d = 0; d < 36; d++) out[o++] = "0123456789abcdef"[v[d]];
    out[o++] = '"';
    out[o] = '\0';
}

/* The strip holds the range and nothing past it. A range of 1,815 s
 * from a half minute is 31 cells of 60 s, the last ending at to (15 s
 * short of a whole cell): a minute row at T-1740, past to but inside
 * the last cell, is not drawn, and the row at T-2400 is cell 19. The
 * same span ending at T-1015 puts D4's open fine bucket at T-1000
 * (test_who_was_here's) in its last cell past to, and the two store
 * rows in cells 7 and 18. Seen red with the cell count held at 144 (the
 * count), with web_store_presence() reading to its last cell's end
 * (cell 30 of the first) and with web_rollup_presence() doing the same
 * (cell 30 of the second). */
static void test_presence_inside_the_range(void) {
    web_qrow_t q[2];
    memset(q, 0, sizeof(q));
    for (int i = 0; i < 2; i++) {
        q[i].tier = WEB_TIER_MINUTE;
        q[i].metric = WM_DEV_PRESENT;
        snprintf(q[i].key, sizeof(q[i].key), "02:00:00:00:00:04");
        q[i].t = i ? T - 1740 : T - 2400;
        q[i].sum = q[i].min = q[i].max = 1;
        q[i].n = 1;
    }
    WT_EQ(web_store_write(&st, q, 2), 0);
    char qs[160], hx[64];
    snprintf(qs, sizeof(qs), "from=%lld&to=%lld", T - 3570, T - 1755);
    WT_EQ(route(&H, "/api/history/devices", qs), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"presence_cell_s\":60,\"presence_cells\":31,\"presence_tier\":\"minute\",");
    const char *row = strstr(b, "{\"mac\":\"02:00:00:00:00:04\"");
    WT_ASSERT(row != NULL);
    int c19[] = { 19 };
    strip_hex(c19, 1, hx);
    WT_HAS(row ? row : "", hx);
    snprintf(qs, sizeof(qs), "from=%lld&to=%lld", T - 2830, T - 1015);
    WT_EQ(route(&H, "/api/history/devices", qs), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"presence_cell_s\":60,\"presence_cells\":31,");
    row = strstr(b, "{\"mac\":\"02:00:00:00:00:04\"");
    WT_ASSERT(row != NULL);
    int c7[] = { 7, 18 };
    strip_hex(c7, 2, hx);
    WT_HAS(row ? row : "", hx);
}

/* A range older than the minute tier is kept: presence from the hour
 * tier, in cells of whole hours. With --web-retain-days 3, a day four
 * days back is 24 cells of an hour, and an hour row for D3 at T-3d-2h
 * is cell 22. Seen red with strips_at() reading the minute tier alone
 * (D3's strip empty). */
static void test_presence_from_the_hour_tier(void) {
    web_qrow_t q;
    memset(&q, 0, sizeof(q));
    q.tier = WEB_TIER_HOUR;
    q.metric = WM_DEV_PRESENT;
    snprintf(q.key, sizeof(q.key), "02:00:00:00:00:03");
    q.t = T - 3 * DY - 2 * HR;
    q.sum = q.min = q.max = 1;
    q.n = 1;
    WT_EQ(web_store_write(&st, &q, 1), 0);
    int keep = ts.retain_days;
    ts.retain_days = 3;
    char qs[160], hx[64];
    snprintf(qs, sizeof(qs), "from=%lld&to=%lld", T - 4 * DY, T - 3 * DY);
    WT_EQ(route(&H, "/api/history/devices", qs), 200);
    ts.retain_days = keep;
    const char *b = body_of(g_out);
    WT_HAS(b, "\"presence_cell_s\":3600,\"presence_cells\":24,\"presence_tier\":\"hour\",");
    const char *row = strstr(b, "{\"mac\":\"02:00:00:00:00:03\"");
    WT_ASSERT(row != NULL);
    int c22[] = { 22 };
    strip_hex(c22, 1, hx);
    WT_HAS(row ? row : "", hx);
    /* A sub-hour range that does not start on the hour: the cells start
     * at the hour that holds from (reported as presence_from), so the
     * hour row covering the range's start is cell 0, not dropped. Seen
     * red with the origin left at from (presence_from T-3d-2h+600 and
     * a blank strip). */
    ts.retain_days = 3;
    snprintf(qs, sizeof(qs), "from=%lld&to=%lld", T - 3 * DY - 2 * HR + 600,
             T - 3 * DY - 2 * HR + 3000);
    WT_EQ(route(&H, "/api/history/devices", qs), 200);
    ts.retain_days = keep;
    b = body_of(g_out);
    char pf[64];
    snprintf(pf, sizeof(pf), "\"presence_from\":%lld,", T - 3 * DY - 2 * HR);
    WT_HAS(b, pf);
    WT_HAS(b, "\"presence_cell_s\":3600,\"presence_cells\":1,\"presence_tier\":\"hour\",");
    row = strstr(b, "{\"mac\":\"02:00:00:00:00:03\"");
    WT_ASSERT(row != NULL);
    int c0[] = { 0 };
    strip_hex(c0, 1, hx);
    WT_HAS(row ? row : "", hx);
    snprintf(qs, sizeof(qs), "from=%lld&to=%lld", T - 4 * DY, T - 3 * DY);
    /* Inside the minute tier's days the same range reads it alone: the
     * hour row is not drawn into minute-sized cells. */
    WT_EQ(route(&H, "/api/history/devices", qs), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"presence_cell_s\":600,\"presence_cells\":144,\"presence_tier\":\"minute\",");
    row = strstr(b, "{\"mac\":\"02:00:00:00:00:03\"");
    strip_hex(NULL, 0, hx);
    WT_HAS(row ? row : "", hx);
}

/* Alerts and flows in the range: never a key, a detail, a cookie or an
 * MQTT username; mqtt_flows is not read at all. Two guards hold each
 * absence (the statement does not name the column, and M4's allow-list
 * would refuse it if it did), so no single mutant reaches a body: each
 * was seen red with both changed together (alerts.detail on the list
 * and selected; rdp_flows.last_cookie and ssh_flows.server_banner the
 * same; mqtt_flows' columns listed and its rows joined). */
static void test_alerts_and_flows(void) {
    char q[160];
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - DY, T);
    WT_EQ(route(&H, "/api/history/alerts", q), 200);
    const char *b = body_of(g_out);
    char want[256];
    snprintf(want, sizeof(want), "\"alerts\":[{\"title\":\"CLEARTEXT_CRED\",\"ip\":\"10.0.0.1\","
             "\"type\":12,\"sev\":1,\"count\":2,\"first_seen\":%lld,\"last_seen\":%lld}],"
             "\"count\":1,\"more\":false}", T - 3 * HR, T - 2 * HR);
    WT_HAS(b, want);
    WT_LACKS(b, "carol");
    WT_LACKS(b, "cred:");
    WT_EQ(route(&H, "/api/history/alerts", "limit=1"), 200);   /* the last 30 d */
    WT_HAS(body_of(g_out), "\"count\":1,\"more\":true}");
    WT_EQ(route(&H, "/api/history/flows", q), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"proto\":\"ssh\",\"src\":\"10.0.0.1\",\"dst\":\"10.0.0.2\",\"count\":3,"
              "\"port\":null,");
    WT_HAS(b, "{\"proto\":\"rdp\",\"src\":\"10.0.0.3\",\"dst\":\"10.0.0.4\",\"count\":2,");
    WT_HAS(b, "{\"proto\":\"smb\",\"src\":\"10.0.0.5\",\"dst\":\"10.0.0.6\",\"count\":7,"
              "\"port\":445,");
    WT_HAS(b, "{\"proto\":\"snmp\",\"src\":\"10.0.0.7\",\"dst\":\"10.0.0.8\",\"count\":6,"
              "\"version\":1,");
    WT_HAS(b, "\"count\":4,\"more\":false}");
    WT_LACKS(b, "dave");
    WT_LACKS(b, "mstshash");
    WT_LACKS(b, "erin");
    WT_LACKS(b, "10.0.0.9");
    WT_LACKS(b, "SSH-2.0");
}

/* The new-since lists of a session as its kinds' identities, by kind. */
static void idents(const char *b, const char *kind, char *out, size_t cap) {
    char want[48];
    snprintf(want, sizeof(want), "\"%s\":{\"rows\":[", kind);
    const char *p = strstr(b, want);
    const char *e = p ? strstr(p, "]") : NULL;
    size_t o = 0;
    out[0] = '\0';
    for (const char *q = p; q && q < e && (q = strstr(q, "{\"ident\":\"")); q += 10) {
        if (q > e) break;
        const char *z = strchr(q + 10, '"');
        o += (size_t)snprintf(out + o, cap - o, "%s%.*s", o ? " " : "",
                              (int)(z - q - 10), q + 10);
    }
}

/* --report's "New since last survey", for each visit. Each window seen
 * red: S3's with the crash fallback dropped (since -1: D1 and D2
 * listed too), the older visits' with the until bound dropped (S2
 * listed D4). */
static void test_new_since(void) {
    char ids[512];
    WT_EQ(route(&H, "/api/sessions/new", "id=1"), 200);
    WT_HAS(body_of(g_out), "\"previous\":null,\"since\":null,\"until\":null,"
                           "\"aps\":null,\"devices\":null,\"probe_clients\":null}");
    /* S2: since S1's end, until S3's start (S2 never ended). */
    WT_EQ(route(&H, "/api/sessions/new", "id=2"), 200);
    const char *b = body_of(g_out);
    char want[256];
    snprintf(want, sizeof(want), "\"since\":%lld,\"until\":%lld,", T - 9 * DY, T - 2 * DY);
    WT_HAS(b, want);
    idents(b, "devices", ids, sizeof(ids));
    WT_ASSERT(!strcmp(ids, "02:00:00:00:00:03 02:00:00:00:00:02"));
    WT_HAS(b, "{\"ident\":\"02:00:00:00:00:02\",\"label\":\"after-s1\",");
    WT_HAS(b, "{\"ident\":\"02:00:00:00:00:03\",\"label\":\"Mid\",");   /* vendor */
    idents(b, "probe_clients", ids, sizeof(ids));
    WT_ASSERT(!strcmp(ids, "06:00:00:00:00:02"));
    idents(b, "aps", ids, sizeof(ids));
    WT_ASSERT(!strcmp(ids, "0a:00:00:00:00:02"));
    WT_HAS(b, "{\"ident\":\"0a:00:00:00:00:02\",\"label\":null,");   /* '' -> - */
    /* S3: S2 never ended, so since is its start. */
    WT_EQ(route(&H, "/api/sessions/new", "id=3"), 200);
    b = body_of(g_out);
    snprintf(want, sizeof(want), "\"previous\":{\"id\":2,");
    WT_HAS(b, want);
    snprintf(want, sizeof(want), "\"since\":%lld,\"until\":%lld,", T - 5 * DY,
             T - 2 * DY + HR);
    WT_HAS(b, want);
    idents(b, "devices", ids, sizeof(ids));
    WT_ASSERT(!strcmp(ids, "02:00:00:00:00:03"));
    /* S4, the latest: --report's window exactly, no upper bound. */
    WT_EQ(route(&H, "/api/sessions/new", "id=4"), 200);
    b = body_of(g_out);
    snprintf(want, sizeof(want), "\"since\":%lld,\"until\":null,", T - 2 * DY + HR);
    WT_HAS(b, want);
    idents(b, "devices", ids, sizeof(ids));
    WT_ASSERT(!strcmp(ids, "02:00:00:00:00:04"));
    WT_HAS(b, "{\"ident\":\"02:00:00:00:00:04\",\"label\":\"Acme\",");   /* '' hostname */
    WT_HAS(b, "\"devices\":{\"rows\":[{\"ident\":\"02:00:00:00:00:04\",\"label\":\"Acme\","
              "\"first_seen\":");
    WT_HAS(b, "],\"total\":1,\"listed\":1}");
    idents(b, "aps", ids, sizeof(ids));
    WT_ASSERT(!strcmp(ids, "0a:00:00:00:00:01"));
    idents(b, "probe_clients", ids, sizeof(ids));
    WT_ASSERT(!strcmp(ids, "06:00:00:00:00:01"));
    /* The wiki's own recipe for the latest visit names the same devices. */
    const char *recipe = NULL;
    for (size_t i = 0; i < web_recipes_n; i++)
        if (strstr(web_recipes[i].title, "between the last two visits"))
            recipe = web_recipes[i].sql;
    WT_ASSERT(recipe != NULL);
    sqlite3 *h = NULL;
    WT_EQ(sqlite3_open_v2(g_db, &h, SQLITE_OPEN_READONLY, NULL), SQLITE_OK);
    sqlite3_stmt *s = NULL;
    WT_EQ(sqlite3_prepare_v2(h, recipe ? recipe : "SELECT 1", -1, &s, NULL), SQLITE_OK);
    char rec[512] = "";
    size_t o = 0;
    while (sqlite3_step(s) == SQLITE_ROW)
        o += (size_t)snprintf(rec + o, sizeof(rec) - o, "%s%s", o ? " " : "",
                              (const char *)sqlite3_column_text(s, 0));
    sqlite3_finalize(s);
    sqlite3_close(h);
    WT_ASSERT(!strcmp(rec, "02:00:00:00:00:04"));
    /* Refusals. */
    static const char *const bad[][3] = {
        { "", "400", "missing_id" }, { "id=0", "400", "bad_id" }, { "id=x", "400", "bad_id" },
        { "id=99", "404", "no_such_session" }, { "id=1&id=2", "400", "repeated_parameter" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        WT_EQ(route(&H, "/api/sessions/new", bad[i][0]), atoi(bad[i][1]));
        snprintf(want, sizeof(want), "{\"error\":\"%s\"}", bad[i][2]);
        WT_HAS(body_of(g_out), want);
    }
}

/* The sessions, newest first, a markup label escaped (seen red with
 * session_json() writing it raw). */
static void test_sessions(void) {
    WT_EQ(route(&H, "/api/sessions", ""), 200);
    const char *b = body_of(g_out);
    char want[256];
    snprintf(want, sizeof(want), "\"sessions\":[{\"id\":4,\"started\":%lld,\"ended\":null,"
             "\"label\":\"\\u003cb\\u003enow\\u003c/b\\u003e\"},{\"id\":3,", T - HR);
    WT_HAS(b, want);
    snprintf(want, sizeof(want), "{\"id\":1,\"started\":%lld,\"ended\":%lld,\"label\":\"office\"}],"
             "\"count\":4,\"more\":false}", T - 10 * DY, T - 9 * DY);
    WT_HAS(b, want);
    WT_LACKS(b, "<b>");
    WT_EQ(route(&H, "/api/sessions", "x=1"), 400);
}

/* A v8 alerts row is a finding (#170): first_seen..last_seen runs from
 * the key's first incident to its latest, quiet gaps included. A range
 * that falls in the gap is not a window the alert fired in, and the
 * range read answers from the latest incident's start. Seen red with
 * alert_start() returning plain first_seen (the gap window lists the
 * finding, and the hit's first_seen is the finding's). */
static void test_alert_finding_gap_is_not_a_hit(void) {
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,"
        "technique,match_ip,match_port,count,reopens,incident_first_seen)"
        " VALUES ('gap:10.0.0.42',%lld,%lld,0,1,'GAP_FINDING','x','T1046',"
        "'10.0.0.42',NULL,9,1,%lld);",
        T - 25 * DY, T - 12 * DY + 60, T - 12 * DY);
    WT_EQ(sdb_exec(g_db, sql), 0);
    char q[160];
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - 20 * DY, T - 19 * DY);
    WT_EQ(route(&H, "/api/history/alerts", q), 200);
    WT_LACKS(body_of(g_out), "GAP_FINDING");
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - 12 * DY - 10,
             T - 12 * DY + 100);
    WT_EQ(route(&H, "/api/history/alerts", q), 200);
    char want[192];
    snprintf(want, sizeof(want), "{\"title\":\"GAP_FINDING\",\"ip\":\"10.0.0.42\","
             "\"type\":0,\"sev\":1,\"count\":9,\"first_seen\":%lld,"
             "\"last_seen\":%lld}", T - 12 * DY, T - 12 * DY + 60);
    WT_HAS(body_of(g_out), want);
    WT_EQ(sdb_exec(g_db, "DELETE FROM alerts WHERE key='gap:10.0.0.42';"), 0);
}

void run_history_tests(void) {
    WT_RUN(test_without_sloth_db);
    WT_RUN(test_page_carries_the_history_view);
    up();
    WT_RUN(test_overview);
    WT_RUN(test_who_was_here);
    WT_RUN(test_presence_inside_the_range);
    WT_RUN(test_presence_from_the_hour_tier);
    WT_RUN(test_alerts_and_flows);
    WT_RUN(test_alert_finding_gap_is_not_a_hit);
    WT_RUN(test_new_since);
    WT_RUN(test_sessions);
    down();
}

#endif
