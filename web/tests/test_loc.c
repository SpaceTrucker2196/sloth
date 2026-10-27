/* sloth's location stamp in slothweb (sloth --location / --gps,
 * 2026-10-27): the stream decoder's one flattened object, the alert
 * page's "loc", and /api/positions in its three renderings. The
 * records are written in the shape src/jsonl.c writes them; the
 * sloth.db is generated from sloth's own DDL (sdb_gen.c). */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_alerts.h"
#include "web_assets.h"
#include "web_ingest.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_loc.h"
#include "web_positions.h"
#include "web_routes.h"
#include "wtest.h"

#define T SDB_NOW

static char g_out[65536];   /* web_server.h WEB_SSE_MAX_UNSENT */

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
    g_out[r.out_len < sizeof(g_out) ? r.out_len : sizeof(g_out) - 1] = '\0';
    return r.status;
}

/* ── the stream decoder ──────────────────────────────────────────── */

static web_jrec_t g_rec;

/* "loc" keeps its scalar members as "loc.<m>" fields; nothing else
 * nested is kept. */
static void test_jl_flattens_loc(void) {
    static const char line[] =
        "{\"type\":\"alert.create\",\"key\":\"k\",\"loc\":{\"lat\":51.5007400,"
        "\"lon\":-0.1246900,\"acc_m\":4.5,\"src\":\"gps\",\"ts\":1800000000,"
        "\"x\":[1,{\"y\":2}]},\"pair\":{\"a\":1}}";
    WT_EQ(web_jl_parse(line, sizeof(line) - 1, &g_rec), WEB_JL_OK);
    double v = 0;
    WT_EQ(web_jl_num(&g_rec, "loc.lat", &v), 1);
    WT_ASSERT(fabs(v - 51.50074) < 1e-9);
    WT_EQ(web_jl_num(&g_rec, "loc.lon", &v), 1);
    WT_ASSERT(fabs(v + 0.12469) < 1e-9);
    WT_ASSERT(web_jl_str(&g_rec, "loc.src") != NULL &&
              !strcmp(web_jl_str(&g_rec, "loc.src"), "gps"));
    WT_EQ(web_jl_int(&g_rec, "loc.ts", -1), 1800000000LL);
    WT_EQ(web_jl_get(&g_rec, "loc")->kind, WEB_J_NEST);
    WT_EQ(web_jl_get(&g_rec, "loc.x")->kind, WEB_J_NEST);
    /* Only "loc" is flattened. */
    WT_ASSERT(web_jl_get(&g_rec, "pair.a") == NULL);
    WT_ASSERT(web_jl_get(&g_rec, "pair") != NULL);
    web_loc_t l;
    WT_EQ(web_loc_from_jrec(&g_rec, &l), 1);
    WT_ASSERT(fabs(l.acc_m - 4.5) < 1e-9 && l.has_acc && !l.has_alt);
}

/* A hostile top-level "loc.lat" cannot sit beside the object's own:
 * the whole line is refused, either order. Seen red with flatten_loc()'s
 * duplicate check removed (WEB_JL_OK). */
static void test_jl_loc_duplicates_refused(void) {
    static const char a[] =
        "{\"type\":\"alert\",\"loc.lat\":1,\"loc\":{\"lat\":2,\"lon\":3}}";
    static const char b[] =
        "{\"type\":\"alert\",\"loc\":{\"lat\":2,\"lat\":3}}";
    static const char c[] =
        "{\"type\":\"alert\",\"loc\":{\"lat\":2},\"loc.lat\":1}";
    WT_EQ(web_jl_parse(a, sizeof(a) - 1, &g_rec), WEB_JL_EDUP);
    WT_EQ(web_jl_parse(b, sizeof(b) - 1, &g_rec), WEB_JL_EDUP);
    WT_EQ(web_jl_parse(c, sizeof(c) - 1, &g_rec), WEB_JL_EDUP);
    static const char d[] = "{\"type\":\"alert\",\"loc\":{\"lat\":2,}}";
    WT_EQ(web_jl_parse(d, sizeof(d) - 1, &g_rec), WEB_JL_ESYNTAX);
    static const char e[] = "{\"type\":\"alert\",\"loc\":[1,2]}";
    WT_EQ(web_jl_parse(e, sizeof(e) - 1, &g_rec), WEB_JL_OK);
    WT_ASSERT(web_jl_get(&g_rec, "loc.0") == NULL);
}

/* The bound the record's text keeps: a line at WEB_JL_MAX_LINE made of
 * one-letter "loc" members, the densest shape there is ("loc.a" and its
 * NUL is exactly `"a":1,`), decodes inside the buffer (the sanitised
 * build would report a write past it) or is refused for its field count,
 * never overrun. */
static void test_jl_loc_dense_line_fits(void) {
    static char line[WEB_JL_MAX_LINE + 1];
    size_t o = (size_t)snprintf(line, sizeof(line), "{\"type\":\"a\",\"loc\":{");
    int k = 0;
    while (o + 16 < WEB_JL_MAX_LINE) {
        o += (size_t)snprintf(line + o, sizeof(line) - o, "%s\"%c%c\":1",
                              k ? "," : "", 'a' + k % 26, 'a' + (k / 26) % 26);
        k++;
        if (k == 26 * 26) break;
    }
    o += (size_t)snprintf(line + o, sizeof(line) - o, "}}");
    int r = web_jl_parse(line, o, &g_rec);
    WT_ASSERT(r == WEB_JL_OK || r == WEB_JL_EFIELDS);
    WT_ASSERT(g_rec.tlen <= WEB_JL_MAX_LINE + 1);
}

/* Out of range, or a source sloth never writes: no location at all.
 * Seen red with web_loc_set()'s range test removed (lat 95 kept). */
static void test_loc_values_checked(void) {
    web_loc_t l;
    WT_EQ(web_loc_set(&l, 95.0, 0, 0, 0, 0, 0, "gps", 1), 0);
    WT_EQ(l.has, 0);
    WT_EQ(web_loc_set(&l, 0, -181.0, 0, 0, 0, 0, "gps", 1), 0);
    WT_EQ(web_loc_set(&l, 0, 0, 0, 0, 0, 0, "<b>", 1), 0);
    WT_EQ(web_loc_set(&l, NAN, 0, 0, 0, 0, 0, "gps", 1), 0);
    WT_EQ(web_loc_set(&l, 1, 2, 1, 3, 1, 4, "fixed", 5), 1);
    char b[256];
    web_jw_t w;
    web_jw_init(&w, b, sizeof(b));
    web_loc_json(&w, &l);
    b[w.len] = '\0';
    WT_HAS(b, "{\"lat\":1.0000000,\"lon\":2.0000000,\"alt_m\":3.0,\"acc_m\":4.0,"
              "\"src\":\"fixed\",\"ts\":5}");
    web_jw_init(&w, b, sizeof(b));
    web_loc_json(&w, NULL);
    b[w.len] = '\0';
    WT_HAS(b, "null");
}

/* The page: the two containers (agreed ids), the module's namespace,
 * the hook each view calls, and the one path it fetches, relative. */
static void test_page_carries_the_location_hooks(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "id=\"loc-alert\"");
    WT_HAS(p, "id=\"loc-drawer\"");
    WT_HAS(p, "window.SlothLocation = { alert: alertHook, drawer: drawerHook };");
    WT_HAS(p, "if (window.SlothLocation) window.SlothLocation.alert(j);");
    WT_HAS(p, "if (window.SlothLocation) window.SlothLocation.drawer(mac);");
    WT_HAS(p, "var q = \"/api/positions?mac=\" + encodeURIComponent(mac);");
    WT_HAS(p, "fetch(q, { credentials: \"same-origin\" })");
}

#ifndef WITH_SQLITE

void run_loc_tests(void) {
    WT_RUN(test_page_carries_the_location_hooks);
    WT_RUN(test_jl_flattens_loc);
    WT_RUN(test_jl_loc_duplicates_refused);
    WT_RUN(test_jl_loc_dense_line_fits);
    WT_RUN(test_loc_values_checked);
    /* Without SQLite there is no sloth.db to read positions from. */
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T;
    WT_EQ(route(&h, "/api/positions", "mac=02:00:5e:00:53:01"), 503);
    WT_HAS(body_of(g_out), "\"error\":\"no_sloth_db\"");
}

#else

#include <sqlite3.h>
#include "wt_tmp.h"

static char g_dir[TEST_TMP_MAX];
static char g_db[128];
static web_slothdb_t sdb;
static web_m4_t m4;
static web_health_t H;
static web_live_t *g_live;
static web_feed_t g_feed;

#define MAC1 "02:00:5e:00:53:01"

static void up_v(int version) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-loc-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, version, 0), 0);
    g_live = calloc(1, sizeof(*g_live));
    WT_ASSERT(g_live != NULL);
    web_live_init(g_live, "unix:/test/sloth.sock");
    web_live_sock_connected(g_live, 0);
    web_feed_reset(&g_feed);
    web_sdb_fns_t fns = { NULL, NULL, NULL, g_live };
    web_slothdb_init(&sdb, g_db, &fns);
    memset(&m4, 0, sizeof(m4));
    m4.sdb = &sdb;
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.m4 = &m4;
    H.live = g_live;
}

static void down(void) {
    web_slothdb_destroy(&sdb);
    web_live_destroy(g_live);
    free(g_live);
    unlink(g_db);
    rmdir(g_dir);
}

/* A sloth.db row stamped by GPS (rowid 1), one by --location (2), one
 * unstamped (3), one whose stored latitude no sloth writes (4). */
static void seed_alerts(void) {
    char sql[2048];
    snprintf(sql, sizeof(sql),
        "INSERT INTO alerts (rowid,key,first_seen,last_seen,type,sev,title,detail,"
        "technique,match_ip,match_port,count,lat,lon,alt_m,acc_m,loc_src,loc_ts) VALUES"
        " (1,'scan:192.0.2.50',%lld,%lld,0,1,'PORT_SCAN','x','T1046','192.0.2.50',0,3,"
        "  51.50074,-0.12469,11.6,4.5,'gps',%lld),"
        " (2,'scan:192.0.2.51',%lld,%lld,0,1,'PORT_SCAN','x','T1046','192.0.2.51',0,3,"
        "  10.0,20.0,NULL,NULL,'fixed',%lld),"
        " (3,'scan:192.0.2.52',%lld,%lld,0,1,'PORT_SCAN','x','T1046','192.0.2.52',0,3,"
        "  NULL,NULL,NULL,NULL,NULL,NULL),"
        " (4,'scan:192.0.2.53',%lld,%lld,0,1,'PORT_SCAN','x','T1046','192.0.2.53',0,3,"
        "  95.0,20.0,NULL,NULL,'gps',%lld);",
        T - 600, T - 60, T - 610, T - 600, T - 60, T - 600,
        T - 600, T - 60, T - 600, T - 60, T - 600);
    WT_EQ(sdb_exec(g_db, sql), 0);
}

static void test_alert_page_loc_from_sloth_db(void) {
    up_v(db_schema_version());
    seed_alerts();
    WT_EQ(route(&H, "/api/alert", "id=d1"), 200);
    WT_HAS(body_of(g_out), "\"loc\":{\"lat\":51.5007400,\"lon\":-0.1246900,\"alt_m\":11.6,"
                           "\"acc_m\":4.5,\"src\":\"gps\"");
    WT_EQ(route(&H, "/api/alert", "id=d2"), 200);
    WT_HAS(body_of(g_out), "\"loc\":{\"lat\":10.0000000,\"lon\":20.0000000,\"alt_m\":null,"
                           "\"acc_m\":null,\"src\":\"fixed\"");
    WT_EQ(route(&H, "/api/alert", "id=d3"), 200);
    WT_HAS(body_of(g_out), "\"loc\":null");
    /* Seen red with web_loc_set()'s range test removed. */
    WT_EQ(route(&H, "/api/alert", "id=d4"), 200);
    WT_HAS(body_of(g_out), "\"loc\":null");
    down();
}

/* A v8 file has no stamp to read: the page says null, and the read of
 * the row still works (the v9 columns are not named). Seen red with
 * row_cols() returning ROW_COLS_LOC whatever the file (503). */
static void test_alert_page_on_v8_file(void) {
    up_v(8);
    WT_EQ(sdb_exec(g_db,
        "INSERT INTO alerts (rowid,key,first_seen,last_seen,type,sev,title,detail,"
        "technique,match_ip,match_port,count) VALUES"
        " (1,'scan:192.0.2.50',100,200,0,1,'PORT_SCAN','x','T1046','192.0.2.50',0,3);"), 0);
    WT_EQ(route(&H, "/api/alert", "id=d1"), 200);
    WT_HAS(body_of(g_out), "\"loc\":null");
    WT_HAS(body_of(g_out), "\"title\":\"PORT_SCAN\"");
    WT_EQ(route(&H, "/api/positions", "mac=" MAC1), 200);
    WT_HAS(body_of(g_out), "\"positions\":[],\"track\":[],\"more\":false");
    down();
}

/* A stream incident carries its stamp from the record that opened it. */
static void test_alert_page_loc_from_stream(void) {
    up_v(db_schema_version());
    char b[1024];
    snprintf(b, sizeof(b),
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"a1f0c3e5d7b9a201\","
        "\"key\":\"scan:192.0.2.77\",\"title\":\"PORT_SCAN\",\"sev\":1,\"ty\":0,"
        "\"count\":1,\"loc\":{\"lat\":-33.8688000,\"lon\":151.2093000,\"acc_m\":6.5,"
        "\"src\":\"gps\",\"ts\":%lld}}\n", T - 60, T - 62);
    web_feed_bytes(&g_feed, g_live, b, strlen(b), 1000);
    WT_EQ(g_live->ninc, 1);
    char q[64];
    snprintf(q, sizeof(q), "id=s%s", g_live->inc[0].hid);
    WT_EQ(route(&H, "/api/alert", q), 200);
    char want[160];
    snprintf(want, sizeof(want), "\"loc\":{\"lat\":-33.8688000,\"lon\":151.2093000,"
             "\"alt_m\":null,\"acc_m\":6.5,\"src\":\"gps\",\"ts\":%lld}", T - 62);
    WT_HAS(body_of(g_out), want);
    down();
}

static void seed_positions(int n) {
    sqlite3 *h = NULL;
    WT_EQ(sqlite3_open(g_db, &h), SQLITE_OK);
    sqlite3_exec(h, "BEGIN", NULL, NULL, NULL);
    for (int i = 0; i < n; i++) {
        char sql[512];
        snprintf(sql, sizeof(sql),
            "INSERT INTO device_positions (mac,last_seen,lat,lon,acc_m,rssi)"
            " VALUES ('" MAC1 "',%lld,%f,11.25,%s,%s);"
            "INSERT INTO sensor_positions (last_seen,lat,lon,alt_m,acc_m,loc_src)"
            " VALUES (%lld,%f,11.25,500,7,'gps');",
            T - 1000 + i, 48.5 + i * 1e-5, i == 0 ? "NULL" : "7.5",
            i == 0 ? "NULL" : "-61", T - 1000 + i, 48.5 + i * 1e-5);
        WT_EQ(sqlite3_exec(h, sql, NULL, NULL, NULL), SQLITE_OK);
    }
    /* Another device's sample and a sample outside any asked span. */
    WT_EQ(sqlite3_exec(h,
        "INSERT INTO device_positions (mac,last_seen,lat,lon) VALUES"
        " ('02:00:5e:00:53:02',1,1.0,2.0);", NULL, NULL, NULL), SQLITE_OK);
    sqlite3_exec(h, "COMMIT", NULL, NULL, NULL);
    sqlite3_close(h);
}

static void test_positions_json(void) {
    up_v(db_schema_version());
    seed_positions(2);
    WT_EQ(route(&H, "/api/positions", "mac=" MAC1), 200);
    WT_HAS(g_out, "Content-Type: application/json\r\n");
    const char *b = body_of(g_out);
    char want[512];
    snprintf(want, sizeof(want),
        "\"positions\":[{\"ts\":%lld,\"lat\":48.5000100,\"lon\":11.2500000,\"acc_m\":7.5,"
        "\"rssi\":-61},{\"ts\":%lld,\"lat\":48.5000000,\"lon\":11.2500000,\"acc_m\":null,"
        "\"rssi\":null}],\"track\":[{\"ts\":%lld,\"lat\":48.5000100,\"lon\":11.2500000},"
        "{\"ts\":%lld,\"lat\":48.5000000,\"lon\":11.2500000}],\"more\":false",
        T - 999, T - 1000, T - 999, T - 1000);
    WT_HAS(b, want);
    WT_HAS(b, "not where the device is");
    WT_LACKS(b, "1.0000000");                /* the other MAC's sample */
    /* A window holding neither sample. */
    WT_EQ(route(&H, "/api/positions", "mac=" MAC1 "&since=1&until=2"), 200);
    WT_HAS(body_of(g_out), "\"positions\":[],\"track\":[]");
    down();
}

static void test_positions_geojson_and_gpx(void) {
    up_v(db_schema_version());
    seed_positions(2);
    WT_EQ(route(&H, "/api/positions", "mac=" MAC1 "&format=geojson"), 200);
    WT_HAS(g_out, "Content-Type: application/geo+json\r\n");
    WT_HAS(g_out, "Content-Disposition: attachment; filename=\"sloth-positions.geojson\"\r\n");
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"type\":\"FeatureCollection\",\"features\":[{\"type\":\"Feature\","
              "\"geometry\":{\"type\":\"Point\",\"coordinates\":[11.2500000,48.5000100]},"
              "\"properties\":{\"kind\":\"heard\",\"mac\":\"" MAC1 "\"");
    /* The track oldest first, [lon, lat] (RFC 7946 §3.1.1). */
    WT_HAS(b, "{\"type\":\"LineString\",\"coordinates\":[[11.2500000,48.5000000],"
              "[11.2500000,48.5000100]]}");
    WT_EQ(route(&H, "/api/positions", "mac=" MAC1 "&format=gpx"), 200);
    WT_HAS(g_out, "Content-Type: application/gpx+xml\r\n");
    b = body_of(g_out);
    WT_HAS(b, "<gpx version=\"1.1\" creator=\"slothweb\" xmlns=\"http://www.topografix.com/GPX/1/1\">");
    WT_HAS(b, "<wpt lat=\"48.5000000\" lon=\"11.2500000\"><time>");
    WT_HAS(b, "<desc>-61 dBm</desc></wpt>");
    WT_HAS(b, "<trk><name>sensor</name><trkseg>\n<trkpt lat=\"48.5000000\" lon=\"11.2500000\">"
              "<ele>500.0</ele><time>");
    WT_HAS(b, "</trkseg></trk>\n</gpx>\n");
    down();
}

static void test_positions_refusals_and_cap(void) {
    up_v(db_schema_version());
    WT_EQ(route(&H, "/api/positions", ""), 400);
    WT_HAS(body_of(g_out), "\"error\":\"bad_mac\"");
    WT_EQ(route(&H, "/api/positions", "mac=02:00:5e:00:53"), 400);
    WT_EQ(route(&H, "/api/positions", "mac=" MAC1 "&format=kml"), 400);
    WT_HAS(body_of(g_out), "\"error\":\"bad_format\"");
    WT_EQ(route(&H, "/api/positions", "mac=" MAC1 "&since=5&until=4"), 400);
    WT_EQ(route(&H, "/api/positions", "mac=" MAC1 "&bogus=1"), 400);
    seed_positions(WEB_POS_MAX + 1);
    WT_EQ(route(&H, "/api/positions", "mac=" MAC1), 200);
    const char *b = body_of(g_out);
    /* The widest rendering of a full answer fits the server's one
     * buffer (the route table's out is 64 KiB here as in web_server.h). */
    WT_EQ(route(&H, "/api/positions", "mac=" MAC1 "&format=geojson"), 200);
    WT_EQ(route(&H, "/api/positions", "mac=" MAC1 "&format=gpx"), 200);
    WT_EQ(route(&H, "/api/positions", "mac=" MAC1), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"more\":true");
    int n = 0;
    for (const char *p = strstr(b, "\"positions\":["); p && (p = strstr(p, "\"rssi\":")); p++) n++;
    WT_EQ(n, WEB_POS_MAX);
    down();
}

void run_loc_tests(void) {
    WT_RUN(test_page_carries_the_location_hooks);
    WT_RUN(test_jl_flattens_loc);
    WT_RUN(test_jl_loc_duplicates_refused);
    WT_RUN(test_jl_loc_dense_line_fits);
    WT_RUN(test_loc_values_checked);
    WT_RUN(test_alert_page_loc_from_sloth_db);
    WT_RUN(test_alert_page_on_v8_file);
    WT_RUN(test_alert_page_loc_from_stream);
    WT_RUN(test_positions_json);
    WT_RUN(test_positions_geojson_and_gpx);
    WT_RUN(test_positions_refusals_and_cap);
}

#endif
