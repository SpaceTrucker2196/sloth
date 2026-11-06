/* GNSS and ADS-B history (web_rfhist.h): the four routes over a
 * sloth.db built from sloth's own DDL (sdb_gen.c) with hand-written
 * gnss_sightings, adsb_aircraft and adsb_sightings rows in the --db
 * writer's shape (src/db.c write_gnss() / write_adsb(), tests/test_db.c
 * pins those), on the pinned clock SDB_NOW. Invented addresses,
 * callsigns and positions (docs/wiki/adsb.md, Privacy).
 *
 * Absence assertions, each seen red under a named mutation and restored:
 * the window with web_sdb_gnss_seen()'s "last_seen >= ?1" dropped (the
 * 3-day-old PRN 9 came back in a 24 h answer); the Local answer with
 * route_m5()'s RF_ADSB_* none_here branch removed (Local served rows);
 * the q refusal with '%' and '_' admitted (q=a% was no longer a 400). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_assets.h"
#include "web_rfhist.h"
#include "web_routes.h"
#include "wtest.h"
#include "wt_tmp.h"

#define T SDB_NOW

static char g_out[65536];

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
    g_out[r.out_len < sizeof(g_out) ? r.out_len : sizeof(g_out) - 1] = '\0';
    return r.status;
}

static web_m4_t     m4;
static web_health_t H;

/* The page's half: both tabs carry their history panels and read the
 * routes; the tables are app.js's DataTable. */
static void test_rfhist_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "<div class=\"hscroll\" id=\"gnss-seen-box\"><div class=\"histrow dhead\" id=\"gnss-seen-thead\"></div><div id=\"gnss-seen-rows\"></div></div>");
    WT_HAS(p, "<div class=\"hscroll\" id=\"adsb-seen-box\"><div class=\"histrow dhead\" id=\"adsb-seen-thead\"></div><div id=\"adsb-seen-rows\"></div></div>");
    WT_HAS(p, "    ST = window.SlothTables.make({ id: \"gnss-seen\", label: \"satellites seen\", box: $(\"gnss-seen-box\"),\n"
              "      head: $(\"gnss-seen-thead\"), reset: $(\"gnss-seen-tools\"), redraw: drawSeen, cols: SEEN_COLS });");
    WT_HAS(p, "    ST = window.SlothTables.make({ id: \"adsb-seen\", label: \"aircraft seen\", box: $(\"adsb-seen-box\"),\n"
              "      head: $(\"adsb-seen-thead\"), reset: $(\"adsb-seen-tools\"), redraw: drawSeen, cols: SEEN_COLS });");
    WT_HAS(p, "    getJSON(\"/api/gnss/seen?days=\" + encodeURIComponent(seenDays())).then(function (j) {");
    WT_HAS(p, "    getJSON(\"/api/gnss/sat?gnssid=\" + gnssid + \"&prn=\" + prn + \"&days=\" + encodeURIComponent(seenDays())).then(function (j) {");
    WT_HAS(p, "    getJSON(\"/api/adsb/seen?days=\" + encodeURIComponent(seenDays()) + \"&limit=\" + SEEN_PAGE +\n"
              "            \"&offset=\" + off + (q ? \"&q=\" + encodeURIComponent(q) : \"\")).then(function (j) {");
    WT_HAS(p, "    getJSON(\"/api/adsb/aircraft?hex=\" + encodeURIComponent(hex) + \"&days=\" + encodeURIComponent(seenDays())).then(function (j) {");
    WT_HAS(p, "    getJSON(\"/api/gnss/tracks?hours=\" + encodeURIComponent(trailHours())).then(function (j) {");
    WT_HAS(p, "<select id=\"gnss-trail-hours\">");
    WT_HAS(p, "      g.fillText(s.id || (s.gnss.charAt(0) + (num(s.svid) ? s.svid : s.prn)), x, y - 9);");
    WT_HAS(p, "    if (q && !/^~?[0-9A-Za-z]{1,8}$/.test(q)) { set(\"adsb-seen-count\", \"search: letters and digits only\"); return; }");
}

/* No sloth.db: 503 no_sloth_db after the query is checked. */
static void test_rfhist_no_db(void) {
    memset(&m4, 0, sizeof(m4));
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.m4 = &m4;
    WT_EQ(route(&H, "/api/gnss/seen", ""), 503);
    WT_HAS(body_of(g_out), "no_sloth_db");
    WT_EQ(route(&H, "/api/adsb/seen", ""), 503);
    WT_EQ(route(&H, "/api/gnss/seen", "days=0"), 400);
    WT_HAS(body_of(g_out), "bad_days");
    WT_EQ(route(&H, "/api/gnss/sat", "prn=5"), 400);
    WT_HAS(body_of(g_out), "bad_gnssid");
    WT_EQ(route(&H, "/api/adsb/aircraft", "hex=A1B2C3"), 400);
    WT_HAS(body_of(g_out), "bad_hex");
    WT_EQ(route(&H, "/api/adsb/seen", "q=a%25"), 400);
    WT_HAS(body_of(g_out), "bad_q");
    WT_EQ(route(&H, "/api/adsb/seen", "q=a_"), 400);
    WT_EQ(route(&H, "/api/adsb/seen", "limit=101"), 400);
    WT_EQ(route(&H, "/api/adsb/seen", "sort=x"), 400);
}

#ifndef WITH_SQLITE

void run_rfhist_tests(void) {
    WT_RUN(test_rfhist_page);
    WT_RUN(test_rfhist_no_db);
}

#else

static char g_dir[TEST_TMP_MAX];
static char g_db[128];
static web_slothdb_t sdb;

static void db_up(int version) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-rfhist-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, version, 0), 0);
    web_slothdb_init(&sdb, g_db, NULL);
    memset(&m4, 0, sizeof(m4));
    m4.sdb = &sdb;
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.m4 = &m4;
}

static void db_down(void) {
    web_slothdb_destroy(&sdb);
    unlink(g_db);
    rmdir(g_dir);
}

static void exec_db(const char *sql) {
    WT_EQ(sdb_exec(g_db, sql), 0);
}

static void seed_gnss(void);

/* The sky trails: every satellite's (el, az) over the window, grouped
 * by satellite and oldest first, one point a bucket (the bucket's
 * newest record), the 3-day-old PRN 9 outside 6 h. Seen red with the
 * GROUP BY's bucket term dropped (PRN 5 collapsed to one point). */
static void test_gnss_tracks(void) {
    db_up(db_schema_version());
    seed_gnss();
    /* A second record inside PRN 5's newest bucket (675 s at 6 h): the
     * bucket shows the newer one. */
    char sql[256];
    snprintf(sql, sizeof(sql), "INSERT INTO gnss_sightings VALUES (%lld,0,5,5,52,131,31.0,0,1);",
             T - 590);
    exec_db(sql);
    WT_EQ(route(&H, "/api/gnss/tracks", ""), 200);
    const char *b = body_of(g_out);
    char want[512];
    snprintf(want, sizeof(want), "\"hours\":6,\"bucket_s\":675,\"have\":true,\"tracks\":["
             "{\"gnssid\":0,\"prn\":5,\"id\":\"G05\",\"pts\":[[%lld,40,120],[%lld,45,125],[%lld,52,131]]},"
             "{\"gnssid\":6,\"prn\":73,\"id\":\"R09\",\"pts\":[[%lld,10,300]]}],"
             "\"total\":2,\"points\":4,\"cut\":false}", T - 3600, T - 1800, T - 590, T - 300);
    WT_HAS(b, want);
    WT_LACKS(b, "\"prn\":9,");
    WT_EQ(route(&H, "/api/gnss/tracks", "hours=24"), 200);
    WT_HAS(body_of(g_out), "\"bucket_s\":2700,");
    WT_EQ(route(&H, "/api/gnss/tracks", "hours=25"), 400);
    WT_HAS(body_of(g_out), "bad_hours");
    WT_EQ(route(&H, "/api/gnss/tracks", "scope=local"), 200);
    WT_HAS(body_of(g_out), "\"total\":2,");
    db_down();
}

/* gnss_sightings rows: PRN 5 three records (two used), PRN 73 one with
 * no C/N0, PRN 9 three days old. */
static void seed_gnss(void) {
    char sql[2048];
    snprintf(sql, sizeof(sql),
        "INSERT INTO gnss_sightings VALUES (%lld,0,5,5,40,120,41.0,1,1);"
        "INSERT INTO gnss_sightings VALUES (%lld,0,5,5,45,125,47.0,1,1);"
        "INSERT INTO gnss_sightings VALUES (%lld,0,5,5,50,130,30.0,0,1);"
        "INSERT INTO gnss_sightings VALUES (%lld,6,73,9,10,300,NULL,0,NULL);"
        "INSERT INTO gnss_sightings VALUES (%lld,0,9,9,20,10,35.0,1,1);",
        T - 3600, T - 1800, T - 600, T - 300, T - 3 * 86400);
    exec_db(sql);
}

/* One row per satellite seen in the window, the most recently seen
 * first; days widens it; one satellite's records oldest first. */
static void test_gnss_seen_and_sat(void) {
    db_up(db_schema_version());
    seed_gnss();
    WT_EQ(route(&H, "/api/gnss/seen", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"days\":1,");
    WT_HAS(b, "\"have\":true,\"sats\":[{\"gnss\":\"GLONASS\",\"gnssid\":6,\"prn\":73,\"svid\":9,");
    WT_HAS(b, "\"records\":1,\"used_pct\":0,\"cn0_max\":null,\"cn0_mean\":null,\"el_max\":10,"
              "\"id\":\"R09\",\"veh\":");
    char want[512];
    snprintf(want, sizeof(want), "{\"gnss\":\"GPS\",\"gnssid\":0,\"prn\":5,\"svid\":5,"
             "\"first_seen\":%lld,\"last_seen\":%lld,\"records\":3,\"used_pct\":67,"
             "\"cn0_max\":47.0,\"cn0_mean\":39.3,\"el_max\":50,\"id\":\"G05\",\"veh\":", T - 3600, T - 600);
    WT_HAS(b, want);
    WT_HAS(b, "\"total\":2,\"more\":false}");
    WT_LACKS(b, "\"prn\":9,");
    WT_EQ(route(&H, "/api/gnss/seen", "days=7"), 200);
    WT_HAS(body_of(g_out), "\"prn\":9,");
    WT_HAS(body_of(g_out), "\"total\":3,");
    WT_EQ(route(&H, "/api/gnss/seen", "limit=1"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,\"more\":true}");
    WT_EQ(route(&H, "/api/gnss/sat", "gnssid=0&prn=5"), 200);
    b = body_of(g_out);
    snprintf(want, sizeof(want), "\"points\":[[%lld,40,120,41.0,1,1],[%lld,45,125,47.0,1,1],"
             "[%lld,50,130,30.0,0,1]],\"total\":3}", T - 3600, T - 1800, T - 600);
    WT_HAS(b, want);
    WT_HAS(b, "\"gnss\":\"GPS\",\"gnssid\":0,\"prn\":5,\"have\":true,");
    WT_EQ(route(&H, "/api/gnss/sat", "gnssid=6&prn=73"), 200);
    snprintf(want, sizeof(want), "\"points\":[[%lld,10,300,null,0,null]]", T - 300);
    WT_HAS(body_of(g_out), want);
    /* The receiver is the host's own: every scope. */
    WT_EQ(route(&H, "/api/gnss/seen", "scope=local"), 200);
    WT_HAS(body_of(g_out), "\"total\":2,");
    WT_LACKS(body_of(g_out), "out_of_scope");
    db_down();
}

static void seed_adsb(void) {
    char sql[4096];
    snprintf(sql, sizeof(sql),
        "INSERT INTO adsb_aircraft VALUES ('a1b2c3',0,%lld,%lld,%lld,2,5,'TST123','7700','A3',"
        "'adsb_icao',1,12000,34000,451.2,-18.4,2210,1);"
        "INSERT INTO adsb_aircraft VALUES ('~00abcd',1,%lld,%lld,%lld,1,1,NULL,NULL,NULL,"
        "'tisb_other',0,2550,2550,NULL,NULL,NULL,0);"
        "INSERT INTO adsb_aircraft VALUES ('0d0e0f',0,%lld,%lld,%lld,1,2,'OLD9',NULL,'A1',"
        "'mode_s',0,NULL,NULL,NULL,NULL,NULL,0);"
        "INSERT INTO adsb_sightings (last_seen,hex,heard,flight,squawk,emergency,category,"
        "on_ground,alt_baro,alt_band,gs,track,baro_rate,lat,lon,rssi,messages,source_type)"
        " VALUES (%lld,'a1b2c3',%lld,'TST123','2201','none','A3',0,34000,16,451.2,271.5,-64,"
        "10.12345,20.54321,-18.4,2210,'adsb_icao');"
        "INSERT INTO adsb_sightings (last_seen,hex,heard,flight,squawk,emergency,category,"
        "on_ground,alt_baro,alt_band,gs,track,lat,lon)"
        " VALUES (%lld,'a1b2c3',NULL,'TST123','7700','general','A3',0,12000,10,300,90,"
        "10.2,20.6);",
        T - 7200, T - 60, T - 600, T - 1800, T - 1700, T - 1800,
        T - 10 * 86400, T - 9 * 86400, T - 10 * 86400, T - 7200, T - 7201, T - 60);
    exec_db(sql);
}

/* The inventory, newest first, a page at a time; q a hex or callsign
 * prefix, any case; one aircraft's row and its sightings oldest first
 * as compact rows; Local out_of_scope with the query still checked. */
static void test_adsb_seen_and_aircraft(void) {
    db_up(db_schema_version());
    seed_adsb();
    WT_EQ(route(&H, "/api/adsb/seen", ""), 200);
    const char *b = body_of(g_out);
    char want[1024];
    snprintf(want, sizeof(want), "\"have\":true,\"aircraft\":[{\"hex\":\"a1b2c3\",\"non_icao\":0,"
             "\"first_seen\":%lld,\"last_seen\":%lld,\"visits\":2,\"sightings\":5,"
             "\"flight\":\"TST123\",\"squawk\":\"7700\",\"category\":\"A3\","
             "\"source_type\":\"adsb_icao\",\"emergency_seen\":1,\"alt_min\":12000,"
             "\"alt_max\":34000,\"gs_max\":451.2,\"rssi_max\":-18.4,\"messages\":2210,"
             "\"pos_seen\":1},{\"hex\":\"~00abcd\",", T - 7200, T - 60);
    WT_HAS(b, want);
    WT_HAS(b, "\"flight\":\"\",\"squawk\":\"\",\"category\":\"\",\"source_type\":\"tisb_other\"");
    WT_HAS(b, "\"total\":2,\"more\":false}");
    WT_LACKS(b, "0d0e0f");                      /* 9 days: outside 7 */
    WT_EQ(route(&H, "/api/adsb/seen", "days=30"), 200);
    WT_HAS(body_of(g_out), "\"hex\":\"0d0e0f\"");
    WT_EQ(route(&H, "/api/adsb/seen", "limit=1"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,\"more\":true}");
    WT_EQ(route(&H, "/api/adsb/seen", "limit=1&offset=1"), 200);
    WT_HAS(body_of(g_out), "\"aircraft\":[{\"hex\":\"~00abcd\"");
    WT_EQ(route(&H, "/api/adsb/seen", "q=A1B"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_HAS(body_of(g_out), "\"hex\":\"a1b2c3\"");
    WT_EQ(route(&H, "/api/adsb/seen", "q=tst"), 200);
    WT_HAS(body_of(g_out), "\"hex\":\"a1b2c3\"");
    WT_EQ(route(&H, "/api/adsb/seen", "q=~00"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_EQ(route(&H, "/api/adsb/seen", "q=zz"), 200);
    WT_HAS(body_of(g_out), "\"aircraft\":[],\"total\":0,");
    WT_EQ(route(&H, "/api/adsb/aircraft", "hex=a1b2c3"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"aircraft\":{\"hex\":\"a1b2c3\",");
    snprintf(want, sizeof(want), "\"sightings\":[[%lld,%lld,34000,10.12345,20.54321,451,272,-64,"
             "-18.4,\"2201\",\"TST123\",\"none\"],[%lld,null,12000,10.20000,20.60000,300,90,null,"
             "null,\"7700\",\"TST123\",\"general\"]],\"total\":2}", T - 7200, T - 7201, T - 60);
    WT_HAS(b, want);
    WT_EQ(route(&H, "/api/adsb/aircraft", "hex=ffffff"), 200);
    WT_HAS(body_of(g_out), "\"aircraft\":null,");
    WT_HAS(body_of(g_out), "\"sightings\":[],\"total\":0}");
    /* Local: the SDR is passive radio. */
    WT_EQ(route(&H, "/api/adsb/seen", "scope=local"), 200);
    WT_HAS(body_of(g_out), "\"out_of_scope\":true,\"reason\":\"aircraft are the ADS-B decoder");
    WT_LACKS(body_of(g_out), "a1b2c3");
    WT_EQ(route(&H, "/api/adsb/aircraft", "scope=local&hex=a1b2c3"), 200);
    WT_HAS(body_of(g_out), "\"out_of_scope\":true");
    WT_EQ(route(&H, "/api/adsb/aircraft", "scope=local&hex=zz"), 400);
    WT_EQ(route(&H, "/api/adsb/seen", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "\"total\":2,");
    db_down();
}

/* A sloth.db from before the tables: an empty answer that says so,
 * never an error. */
static void test_rfhist_older_file(void) {
    db_up(11);
    WT_EQ(route(&H, "/api/adsb/seen", ""), 200);
    WT_HAS(body_of(g_out), "\"have\":false,\"aircraft\":[],\"total\":0,");
    WT_EQ(route(&H, "/api/adsb/aircraft", "hex=a1b2c3"), 200);
    WT_HAS(body_of(g_out), "\"have\":false,\"aircraft\":null,");
    db_down();
    db_up(9);
    WT_EQ(route(&H, "/api/gnss/seen", ""), 200);
    WT_HAS(body_of(g_out), "\"have\":false,");
    db_down();
}

void run_rfhist_tests(void) {
    WT_RUN(test_rfhist_page);
    WT_RUN(test_rfhist_no_db);
    WT_RUN(test_gnss_seen_and_sat);
    WT_RUN(test_gnss_tracks);
    WT_RUN(test_adsb_seen_and_aircraft);
    WT_RUN(test_rfhist_older_file);
}

#endif
