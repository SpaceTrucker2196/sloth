/* The merged views (web_fleetview.h; owner request 2026-11-11): two
 * sites' rows seeded into peer_sightings beside this site's sloth.db and
 * BLE table, and the list routes asked through the router: a row both
 * sites hold is the local row with "sites", a row only a peer holds is
 * added "remote" after the local rows, fleet=0 and no peer configured
 * answer the route's own bytes exactly, the cap is held and said, the
 * remote rows feed nothing (the export, the risk members, the count),
 * and a peer's hostile strings come out escaped. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "web_assets.h"
#include "web_ble.h"
#include "web_fleet.h"
#include "web_fleetview.h"
#include "web_jsonl.h"
#include "web_routes.h"
#include "web_secret.h"
#include "web_slothdb.h"
#include "web_store.h"
#include "wtest.h"
#include "wt_tmp.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#include "sdb_gen.h"
#endif

/* fleet= taken out as scope= is: the rest byte for byte, each value and
 * malformed form refused by its word. */
static void test_take(void) {
    char rest[512], err[48];
    int mode = -1;
    WT_EQ(web_fv_take("limit=5&fleet=0&sort=last", rest, sizeof(rest), &mode, err, sizeof(err)), 0);
    WT_ASSERT(!strcmp(rest, "limit=5&sort=last"));
    WT_EQ(mode, WEB_FV_OFF);
    WT_EQ(web_fv_take("fleet=1", rest, sizeof(rest), &mode, err, sizeof(err)), 0);
    WT_ASSERT(!strcmp(rest, ""));
    WT_EQ(mode, WEB_FV_ON);
    WT_EQ(web_fv_take("q=fleetwood", rest, sizeof(rest), &mode, err, sizeof(err)), 0);
    WT_ASSERT(!strcmp(rest, "q=fleetwood"));
    WT_EQ(mode, WEB_FV_DEFAULT);
    WT_EQ(web_fv_take("fleet=2", rest, sizeof(rest), &mode, err, sizeof(err)), -1);
    WT_ASSERT(!strcmp(err, "bad_fleet"));
    WT_EQ(web_fv_take("fleet=1&fleet=1", rest, sizeof(rest), &mode, err, sizeof(err)), -1);
    WT_ASSERT(!strcmp(err, "repeated_parameter"));
    WT_EQ(web_fv_take("fleet=", rest, sizeof(rest), &mode, err, sizeof(err)), -1);
    WT_ASSERT(!strcmp(err, "empty_value"));
    WT_EQ(web_fv_take("a=1&&b=2", rest, sizeof(rest), &mode, err, sizeof(err)), -1);
    WT_ASSERT(!strcmp(err, "bad_query"));
}

/* Every member the merge adds, held to web_secret.h as the export's are. */
static void test_members_are_not_secret(void) {
    static const char *const M[] = {
        "fleet", "peers", "site", "site_label", "sites", "label", "remote", "remote_cap",
        "remote_more", "remote_off", "partial", "note", "ap_rows", "kind", "probe_rows", NULL };
    for (int i = 0; M[i]; i++) WT_EQ(web_sdb_is_secret("peer_sightings", M[i], "TEXT"), 0);
}

/* The page: a remote row's grey state from the tokens alone, the host's
 * name and every peer string set as text, the choice kept per view and
 * hidden with no peer, This site asked as fleet=0. Whole functions
 * pinned (agents/AGENTS.md: single lines miss their neighbours). */
static void test_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, ".dt-row.remote, .dt-row.remote span { color: var(--tui-dim); font-weight: 400; }");
    WT_HAS(p, "  function fvQuery(v) { return FV.peers.length && !fvAll(v) ? \"&fleet=0\" : \"\"; }");
    WT_HAS(p, "  function fvMark(d) {\n"
              "    if (d.remote === true) {\n"
              "      var sp = el(\"span\", \"fv-site\", fvCut(fvName(d)));\n"
              "      sp.title = \"heard by \" + (d.sites || []).map(fvName).join(\", \");\n"
              "      return sp;\n"
              "    }\n");
    WT_HAS(p, "      s.parentNode.hidden = !FV.peers.length;\n"
              "      s.value = prefGet(\"fleet.\" + v) === \"here\" ? \"here\" : \"all\";");
    WT_HAS(p, "prefSet(\"fleet.devices\", this.value); devices();");
    WT_HAS(p, "prefSet(\"fleet.aps\", this.value); wifiAps();");
    WT_HAS(p, "prefSet(\"fleet.ble\", this.value); bleLoad();");
    WT_HAS(p, "    if (d.remote === true) return fillRemote(r, d);");
    WT_HAS(p, "    if (d.remote === true) return bleRemoteRow(d, now);");
    WT_HAS(p, "    sw.style.background = rem ? \"var(--tui-dim)\" : keyColor(String(a.bssid));");
    WT_HAS(p, "<select id=\"d-sites\"");
    WT_HAS(p, "<select id=\"w-sites\"");
    WT_HAS(p, "<select id=\"b-sites\"");
    /* The Probes tab: its choice kept as the others are, its grey rows
     * from the same mark, a grey station's click the device drawer, a
     * grey network's its hosts, and the drawer naming what each host
     * heard a station probe for. */
    WT_HAS(p, "<select id=\"pr-sites\"");
    WT_HAS(p, "  var FV_SEL = { devices: \"d-sites\", aps: \"w-sites\", ble: \"b-sites\", probes: \"pr-sites\" };");
    WT_HAS(p, "    prefSet(\"fleet.probes\", this.value);\n"
              "    if (window.SlothProbes) SlothProbes.show();\n");
    WT_HAS(p, "    fvQuery: fvQuery, fvAll: fvAll });");
    WT_HAS(p, "    var rows = (f.rows || []).concat(f.ap_rows || [], f.probe_rows || []);");
    WT_HAS(p, "               x.kind === \"probe\" ? \"probed for \" + x.ssid : x.ssid ? \"ssid \" + x.ssid : null,");
    WT_HAS(p, "      if (d.remote === true) { box.appendChild(clientRemote(d)); return; }");
    WT_HAS(p, "      if (s.remote === true) { ssidRemote(box, s); return; }");
    WT_HAS(p, "    row.addEventListener(\"click\", function () { H.openDrawer(String(d.mac)); });\n"
              "    H.drawStrip(cv, null, CELLS, -1);\n"
              "    return row;\n");
    WT_HAS(p, "    row.addEventListener(\"click\", function () { P.ssOpen = open ? null : key; ssidsDraw(); });");
    WT_HAS(p, "\"&offset=\" + off + H.fvQuery(\"probes\")).then(function (j) {");
    WT_LACKS(p, "innerHTML");
    WT_LACKS(p, "not heard here");
}

#ifdef WITH_SQLITE

#define T SDB_NOW

static char g_dir[TEST_TMP_MAX];
static char g_db[TEST_TMP_MAX + 32], g_store[TEST_TMP_MAX + 32];
static web_store_t   S;
static web_slothdb_t SDB;
static web_fleet_t   F;
static web_ble_t     B;
static web_m4_t      M4;
static web_health_t  H;
static char          OUT[65536];

static int sql_on(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    int rc = sqlite3_open(path, &h);
    if (rc == SQLITE_OK) rc = sqlite3_exec(h, sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) fprintf(stderr, "    sql: %s\n", sqlite3_errmsg(h));
    sqlite3_close(h);
    return rc == SQLITE_OK ? 0 : -1;
}

static void feed_ble(const char *addr, const char *name, long long last) {
    static web_jrec_t r;
    char line[2048];
    snprintf(line, sizeof(line),
             "{\"type\":\"ble_device\",\"ts\":%lld,\"addr\":\"%s\",\"addr_type\":0,"
             "\"sensor\":\"ble\",\"iface\":\"bluetooth-monitor\",\"adapter\":0,\"sampled\":0,"
             "\"channel\":-1,\"last_pdu\":\"ADV_IND\",\"pdu_mask\":1,\"name\":\"%s\","
             "\"name_complete\":1,\"uuid16\":-1,\"mfr_id\":-1,\"mfr_subtype\":-1,"
             "\"svc_data_uuid16\":-1,\"appearance\":-1,\"hid\":0,\"tx_power\":-128,"
             "\"flags\":-1,\"has_rssi\":1,\"rssi\":-60,\"rssi_best\":-55,\"adv_count\":5,"
             "\"watch_category\":\"\",\"ext_adv\":0,\"primary_phy\":0,\"secondary_phy\":0,"
             "\"adv_sid\":-1,\"first_seen\":%lld,\"last_seen\":%lld}",
             last, addr, name, last - 100, last);
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_ble_record(&B, &r, 1000);
}

/* This site: three devices and an AP in sloth.db, an advertiser in the
 * BLE table. Two peers, beta (its export labelled it beta-site) and
 * gamma (no label), and a third, old, whose rows linger but which is no
 * longer named. */
static void up(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-fleetview-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    snprintf(g_store, sizeof(g_store), "%s/slothweb.db", g_dir);
    WT_EQ(sdb_make(g_db, db_schema_version(), 0), 0);
    char sql[4096];
    snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,vendor,is_ap,signal_dbm,risk_level,first_seen,last_seen) VALUES"
        " ('aa:00:00:00:00:01','Apple',0,-41,2,%lld,%lld),"
        " ('aa:00:00:00:00:02','Here',0,-50,0,%lld,%lld),"
        " ('aa:00:00:00:00:03','Other',0,-70,0,%lld,%lld);"
        "INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,enc,first_seen,last_seen) VALUES"
        " ('0a:00:00:00:00:01','HomeNet',-45,11,'WPA2',%lld,%lld);",
        T - 900, T - 30, T - 900, T - 20, T - 900, T - 10, T - 900, T - 15);
    WT_EQ(sdb_exec(g_db, sql), 0);
    web_slothdb_init(&SDB, g_db, NULL);
    char err[512];
    WT_EQ(web_store_open(&S, g_store, err, sizeof(err)), 0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO peer_sites (peer,url,label) VALUES"
        " ('beta','http://100.64.0.2:8770','beta-site'),"
        " ('gamma','http://100.64.0.3:8770',''),"
        " ('old','http://100.64.0.4:8770','old-site');"
        "INSERT INTO peer_sightings (peer,kind,key,label,vendor,rssi,first_seen,last_seen,extra)"
        " VALUES"
        " ('beta','wifi','aa:00:00:00:00:01','HomeNet','Apple',-50,%lld,%lld,"
        "  '{\"bssid\":\"0a:00:00:00:00:01\",\"is_ap\":false}'),"
        " ('gamma','wifi','aa:00:00:00:00:01','HomeNet','Apple',-60,%lld,%lld,"
        "  '{\"bssid\":null,\"is_ap\":false}'),"
        /* Held here but not matching vendor:Evil locally: never remote. */
        " ('beta','wifi','aa:00:00:00:00:03','','Evil Corp',-66,%lld,%lld,'{}'),"
        /* Only beta: a hostile vendor and SSID. */
        " ('beta','wifi','bb:00:00:00:00:01','x\"},{\"remote\":false,\"mac\":\"1',"
        "  'Evil<script>alert(1)</script>',-61,%lld,%lld,"
        "  '{\"bssid\":\"0b:00:00:00:00:01\",\"is_ap\":false}'),"
        /* sloth's 0: never heard on the air, no reading. */
        " ('gamma','wifi','bb:00:00:00:00:02','','Quiet',0,%lld,%lld,'{\"is_ap\":false}'),"
        /* Both peers, neither here. */
        " ('beta','wifi','bb:00:00:00:00:03','','Both',-70,%lld,%lld,'{}'),"
        " ('gamma','wifi','bb:00:00:00:00:03','','Both',-72,%lld,%lld,'{}'),"
        " ('old','wifi','cc:00:00:00:00:01','','Gone',-40,%lld,%lld,'{}'),"
        " ('beta','ap','0a:00:00:00:00:01','HomeNet','',-48,%lld,%lld,"
        "  '{\"channel\":11,\"enc\":\"WPA2\"}'),"
        " ('gamma','ap','0b:00:00:00:00:01','CafeFree','Cisco',-58,%lld,%lld,"
        "  '{\"channel\":6,\"enc\":\"OPEN\"}'),"
        " ('beta','ble','02:de:00:00:00:01','demo-a','phone',-62,%lld,%lld,"
        "  '{\"addr_type\":\"P\"}'),"
        " ('beta','ble','02:de:00:00:00:09','<img src=x onerror=1>','phone',-77,%lld,%lld,"
        "  '{\"addr_type\":\"R\"}');",
        T - 800, T - 100, T - 700, T - 50, T - 600, T - 60, T - 500, T - 40,
        T - 500, T - 300, T - 400, T - 200, T - 450, T - 100, T - 400, T - 5,
        T - 600, T - 90, T - 600, T - 80, T - 300, T - 70, T - 300, T - 25);
    WT_EQ(sql_on(g_store, sql), 0);
    web_fleet_peer_cfg_t pc[2];
    WT_EQ(web_fleet_parse_peer("beta=http://100.64.0.2:8770", &pc[0], err, sizeof(err)), 0);
    WT_EQ(web_fleet_parse_peer("gamma=http://100.64.0.3:8770", &pc[1], err, sizeof(err)), 0);
    web_fleet_init(&F, pc, 2, 60, 0, &S);
    WT_EQ(web_ble_init(&B, 0), 0);
    feed_ble("02:de:00:00:00:01", "demo-a", T - 10);
    memset(&M4, 0, sizeof(M4));
    M4.sdb = &SDB;
    M4.fleet = &F;
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.m4 = &M4;
    H.ble = &B;
}

static void down(void) {
    web_ble_destroy(&B);
    web_fleet_destroy(&F);
    web_slothdb_destroy(&SDB);
    web_store_close(&S);
    static const char *const names[] = {
        "sloth.db", "sloth.db-wal", "sloth.db-shm", "sloth.db-journal",
        "slothweb.db", "slothweb.db-wal", "slothweb.db-shm", "slothweb.db-journal" };
    char p[TEST_TMP_MAX + 32];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(p, sizeof(p), "%s/%s", g_dir, names[i]);
        unlink(p);
    }
    rmdir(g_dir);
}

/* GET path?query through the router; the body (after the header) into
 * OUT's tail, returned, NUL-ended; *status set. */
static const char *get(const char *path, const char *query, int *status, size_t *blen) {
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    memset(&r, 0, sizeof(r));
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    snprintf(rq.path, sizeof(rq.path), "%s", path);
    snprintf(rq.query, sizeof(rq.query), "%s", query);
    *status = 0;
    if (web_route(&rq, &H, 1, OUT, sizeof(OUT) - 1, &r) != 0) return "";
    OUT[r.out_len] = '\0';
    *status = r.status;
    char *b = strstr(OUT, "\r\n\r\n");
    if (!b) return "";
    b += 4;
    if (blen) *blen = r.out_len - (size_t)(b - OUT);
    return b;
}

static int count_of(const char *s, const char *needle) {
    int n = 0;
    for (const char *p = s; (p = strstr(p, needle)); p += strlen(needle)) n++;
    return n;
}

/* The WiFi Devices list: the shared rows gain sites, the peers' own
 * rows follow, the peer no longer named and the key held here are not
 * among them. "count" stays the local rows'; a remote row carries no
 * risk, z, anomaly or presence member. */
static void test_devices_merge(void) {
    up();
    int st;
    const char *b = get("/api/devices", "sort=last", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "\"count\":3,");
    WT_HAS(b, "\"sites\":[{\"site\":\"gamma\",\"label\":null,\"first_seen\":1792626500,"
              "\"last_seen\":1792627150},{\"site\":\"beta\",\"label\":\"beta-site\","
              "\"first_seen\":1792626400,\"last_seen\":1792627100}]}");
    /* The remote rows, newest first (sort=last), after the local ones. */
    const char *r1 = strstr(b, "{\"mac\":\"bb:00:00:00:00:01\"");
    const char *r3 = strstr(b, "{\"mac\":\"bb:00:00:00:00:03\"");
    const char *l3 = strstr(b, "{\"mac\":\"aa:00:00:00:00:03\"");
    WT_ASSERT(r1 && r3 && l3 && l3 < r1 && r1 < r3);
    WT_HAS(b, "\"remote\":true,\"site\":\"beta\",\"site_label\":\"beta-site\"");
    WT_HAS(b, "{\"mac\":\"bb:00:00:00:00:02\",\"random\":true,\"vendor\":\"Quiet\",\"ssid\":null,"
              "\"signal\":null,\"is_ap\":false,");
    WT_EQ(count_of(b, "\"remote\":true"), 3);
    /* aa:03 is this site's (sloth.db holds it): a local row with a site,
     * never a remote one. */
    WT_EQ(count_of(b, "\"aa:00:00:00:00:03\""), 1);
    WT_ASSERT(!strstr(b, "cc:00:00:00:00:01"));
    WT_EQ(count_of(b, "\"risk\":"), 3);
    WT_EQ(count_of(b, "\"anomalies\":"), 3);
    WT_HAS(b, ",\"fleet\":{\"peers\":[{\"site\":\"beta\",\"label\":\"beta-site\"},"
              "{\"site\":\"gamma\",\"label\":null}],\"remote\":3,\"remote_cap\":100,"
              "\"remote_more\":false,\"partial\":false,\"remote_off\":null}}\n");
    /* The hostile strings, escaped: no markup, and no member they tried
     * to close the row with. */
    WT_ASSERT(!strstr(b, "<script>"));
    WT_HAS(b, "Evil\\u003cscript\\u003e");
    WT_ASSERT(!strstr(b, "x\"},{\"remote\":false"));
    WT_EQ(count_of(b, "\"remote\":false"), 0);
    /* Sorted by the same column: by MAC, the remote rows in MAC order. */
    b = get("/api/devices", "sort=mac", &st, NULL);
    r1 = strstr(b, "\"bb:00:00:00:00:01\"");
    const char *r2 = strstr(b, "\"bb:00:00:00:00:02\"");
    r3 = strstr(b, "\"bb:00:00:00:00:03\"");
    WT_ASSERT(r1 && r2 && r3 && r1 < r2 && r2 < r3);
    down();
}

/* The filter: a term a peer row can answer is applied to it, one it
 * cannot leaves the remote rows out and says so; a key held here that
 * the filter hides locally is still not a remote row. A page that does
 * not end the local list carries none. Seen red with held_here()
 * answering 0 (aa:03 then a remote row under vendor:Evil). */
static void test_devices_filters_and_pages(void) {
    up();
    int st;
    const char *b = get("/api/devices", "q=vendor%3AEvil", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "\"count\":0,");
    WT_EQ(count_of(b, "\"remote\":true"), 1);
    WT_HAS(b, "{\"mac\":\"bb:00:00:00:00:01\"");
    WT_ASSERT(!strstr(b, "aa:00:00:00:00:03"));
    b = get("/api/devices", "q=risk%3A2", &st, NULL);
    WT_EQ(st, 200);
    WT_EQ(count_of(b, "\"remote\":true"), 0);
    WT_HAS(b, "\"remote_off\":\"query\"");
    b = get("/api/devices", "q=-vendor%3AEvil+seen%3A%3C1h", &st, NULL);
    WT_EQ(count_of(b, "\"remote\":true"), 2);
    WT_ASSERT(!strstr(b, "bb:00:00:00:00:01"));
    b = get("/api/devices", "limit=1", &st, NULL);
    WT_HAS(b, "\"more\":true");
    WT_EQ(count_of(b, "\"remote\":true"), 0);
    WT_HAS(b, "\"remote_off\":\"not_last_page\"");
    b = get("/api/devices", "limit=2&offset=2", &st, NULL);
    WT_HAS(b, "\"more\":false");
    WT_EQ(count_of(b, "\"remote\":true"), 3);
    down();
}

/* fleet=0 is the route's own answer, byte for byte; so is every answer
 * without a peer configured, and under a capture scope. Seen red with
 * web_fv_on() ignoring WEB_FV_OFF. */
static void test_local_only_is_unchanged(void) {
    up();
    static char a[65536], c[65536];
    static const char *const P[][2] = {
        { "/api/devices", "sort=last" }, { "/api/wifi/aps", "limit=100" },
        { "/api/ble", "limit=200" }, { "/api/device/bb%3A00%3A00%3A00%3A00%3A01", "" },
        { "/api/device/aa:00:00:00:00:01", "" }, { "/api/ble/02:de:00:00:00:09", "" },
    };
    for (size_t i = 0; i < sizeof(P) / sizeof(P[0]); i++) {
        int s1, s2;
        size_t l1 = 0, l2 = 0;
        char q[128];
        snprintf(q, sizeof(q), "%s%sfleet=0", P[i][1], P[i][1][0] ? "&" : "");
        const char *x = get(P[i][0], q, &s1, &l1);
        memcpy(a, x, l1 + 1);
        /* Today's answer: no fleet attached at all. */
        M4.fleet = NULL;
        const char *y = get(P[i][0], P[i][1], &s2, &l2);
        memcpy(c, y, l2 + 1);
        M4.fleet = &F;
        WT_EQ(s1, s2);
        WT_EQ(l1, l2);
        WT_ASSERT(l1 == l2 && !memcmp(a, c, l1));
        WT_ASSERT(!strstr(a, "\"fleet\":"));
        /* A fleet with no peer named answers the same. */
        int np = F.npeer;
        F.npeer = 0;
        y = get(P[i][0], P[i][1], &s2, &l2);
        F.npeer = np;
        WT_ASSERT(l1 == l2 && !memcmp(a, y, l1));
    }
    int st;
    const char *b = get("/api/devices", "scope=monitor", &st, NULL);
    WT_EQ(st, 200);
    WT_ASSERT(!strstr(b, "\"fleet\":"));
    b = get("/api/devices", "fleet=2", &st, NULL);
    WT_EQ(st, 400);
    WT_HAS(b, "bad_fleet");
    down();
}

/* At most WEB_FV_REMOTE_MAX remote rows, and the answer says it cut. */
static void test_cap(void) {
    up();
    sqlite3 *h = NULL;
    WT_EQ(sqlite3_open(g_store, &h), SQLITE_OK);
    sqlite3_exec(h, "BEGIN", NULL, NULL, NULL);
    for (int i = 0; i < 150; i++) {
        char sql[256];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO peer_sightings (peer,kind,key,label,vendor,rssi,first_seen,"
                 "last_seen,extra) VALUES ('gamma','wifi','dd:00:00:00:%02x:%02x','','',-80,"
                 "%lld,%lld,'{}')", i / 256, i % 256 + 1, T - 9000, T - 9000 + i);
        WT_EQ(sqlite3_exec(h, sql, NULL, NULL, NULL), SQLITE_OK);
    }
    sqlite3_exec(h, "COMMIT", NULL, NULL, NULL);
    sqlite3_close(h);
    int st;
    const char *b = get("/api/devices", "", &st, NULL);
    WT_EQ(st, 200);
    WT_EQ(count_of(b, "\"remote\":true"), WEB_FV_REMOTE_MAX);
    WT_HAS(b, "\"remote\":100,\"remote_cap\":100,\"remote_more\":true");
    WT_EQ(count_of(b, "\"aa:00:00:00:00:0"), 3);    /* every local row kept */
    down();
}

/* The AP table and the BLE advertisers, each under its own names. */
static void test_aps_and_ble(void) {
    up();
    int st;
    const char *b = get("/api/wifi/aps", "", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "\"sites\":[{\"site\":\"beta\",\"label\":\"beta-site\",");
    WT_HAS(b, "{\"bssid\":\"0b:00:00:00:00:01\",\"ssid\":\"CafeFree\",\"signal\":-58,"
              "\"channel\":6,\"enc\":\"OPEN\",\"vendor\":\"Cisco\",");
    WT_HAS(b, "\"remote\":true,\"site\":\"gamma\",\"site_label\":null");
    WT_HAS(b, "\"count\":1,");
    b = get("/api/ble", "", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "{\"addr\":\"02:de:00:00:00:09\",\"addr_type\":1,\"type\":\"R\",");
    WT_HAS(b, "\"class\":\"b:phone\"");
    WT_ASSERT(!strstr(b, "<img"));
    WT_HAS(b, "\\u003cimg src=x onerror=1\\u003e");
    WT_EQ(count_of(b, "\"remote\":true"), 1);
    WT_HAS(b, "\"sites\":[{\"site\":\"beta\",");
    b = get("/api/ble", "q=02%3Ade%3A00%3A00%3A00%3A00%3A01", &st, NULL);
    WT_EQ(count_of(b, "\"remote\":true"), 0);
    down();
}

/* The drawers: a remote-only address answers with the peers' rows and
 * the names of the hosts that saw it, a local one gains its sites; an
 * address nobody saw is the route's own answer. */
static void test_drawers(void) {
    up();
    int st;
    const char *b = get("/api/device/bb:00:00:00:00:01", "", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "\"record\":null");
    WT_HAS(b, "\"fleet\":{\"remote\":true,\"site\":\"beta\",\"site_label\":\"beta-site\","
              "\"note\":\"seen at beta-site\",\"rows\":[{\"site\":\"beta\",");
    WT_HAS(b, "\"bssid\":\"0b:00:00:00:00:01\"");
    WT_ASSERT(!strstr(b, "not heard"));
    b = get("/api/device/bb:00:00:00:00:03", "", &st, NULL);
    WT_HAS(b, "\"note\":\"seen at gamma, beta-site\"");
    b = get("/api/device/aa:00:00:00:00:01", "", &st, NULL);
    WT_HAS(b, "\"fleet\":{\"remote\":false,");
    WT_HAS(b, "\"note\":null");
    WT_HAS(b, "\"ap_rows\":[]");
    b = get("/api/device/0b:00:00:00:00:01", "", &st, NULL);
    WT_HAS(b, "\"rows\":[],\"ap_rows\":[{\"site\":\"gamma\",\"label\":null,\"kind\":\"ap\",");
    b = get("/api/ble/02:de:00:00:00:09", "", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "\"rows\":[],\"alerts\":[],\"count\":0,\"fleet\":{\"remote\":true,");
    WT_HAS(b, "\"note\":\"seen at beta-site\"");
    b = get("/api/ble/02:de:00:00:00:01", "", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "\"fleet\":{\"remote\":false,");
    b = get("/api/ble/02:de:00:00:00:77", "", &st, NULL);
    WT_EQ(st, 404);
    WT_ASSERT(!strstr(b, "\"fleet\""));
    down();
}

/* The export reads sloth.db and the BLE table, never peer_sightings: a
 * peer's rows never travel back out. Seen red with a peer row inserted
 * into sloth.db's devices (the export then carried bb:01). */
static void test_export_carries_no_peer_row(void) {
    up();
    web_fleet_src_t src = { &SDB, &B, NULL, NULL, NULL, NULL };
    char *body = NULL;
    size_t len = 0;
    int st = 0;
    WT_EQ(web_fleet_export_route(&src, "since=0", T, &body, &len, &st), 0);
    WT_EQ(st, 200);
    WT_ASSERT(body != NULL);
    if (body) {
        char *t = realloc(body, len + 1);
        if (t) { body = t; body[len] = '\0'; }
        WT_HAS(body, "\"aa:00:00:00:00:01\"");
        WT_ASSERT(!strstr(body, "bb:00:00:00:00:0"));
        WT_ASSERT(!strstr(body, "0b:00:00:00:00:01"));
        WT_ASSERT(!strstr(body, "02:de:00:00:00:09"));
        free(body);
    }
    down();
}

/* ── the Probes view ─────────────────────────────────────────────────── */

#define DY 86400LL

/* This site: aa:01 probing for HomeNet and Office in the window, aa:09
 * for OldPlace forty days ago (held, outside the 30-day window). The
 * peers: aa:01 for HomeNet (beta) and CafeFree (gamma); bb:11, only
 * theirs, for CafeFree (both) and HomeNet (beta); bb:12 with a hostile
 * SSID; aa:09/OldPlace (held here); bb:13 a wildcard (no SSID); bb:14
 * sixty days ago; cc:11 from the peer no longer named. */
static void probes_up(void) {
    up();
    char sql[4096];
    snprintf(sql, sizeof(sql),
        "INSERT INTO probe_clients (mac,ssid,signal_dbm,channel,frame_count,presence,"
        "first_seen,last_seen) VALUES ('aa:00:00:00:00:01','HomeNet',-50,6,10,0,%lld,%lld);"
        "INSERT INTO pnl_clients (mac,mac_random,probe_count,os_fp,phy,first_seen,last_seen)"
        " VALUES ('aa:00:00:00:00:01',0,4,'','',%lld,%lld),"
        " ('aa:00:00:00:00:09',0,1,'','',%lld,%lld);"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) VALUES"
        " ('aa:00:00:00:00:01','HomeNet',%lld,%lld),"
        " ('aa:00:00:00:00:01','Office',%lld,%lld),"
        " ('aa:00:00:00:00:09','OldPlace',%lld,%lld);",
        T - 900, T - 30, T - 900, T - 30, T - 40 * DY, T - 35 * DY,
        T - 900, T - 30, T - 800, T - 40, T - 40 * DY, T - 35 * DY);
    WT_EQ(sdb_exec(g_db, sql), 0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO peer_sightings (peer,kind,key,label,vendor,rssi,first_seen,last_seen,extra)"
        " VALUES"
        " ('beta','probe','aa:00:00:00:00:01|HomeNet','HomeNet','',NULL,%lld,%lld,"
        "  '{\"mac\":\"aa:00:00:00:00:01\"}'),"
        " ('gamma','probe','aa:00:00:00:00:01|CafeFree','CafeFree','',NULL,%lld,%lld,"
        "  '{\"mac\":\"aa:00:00:00:00:01\"}'),"
        " ('beta','probe','bb:00:00:00:00:11|CafeFree','CafeFree','',NULL,%lld,%lld,"
        "  '{\"mac\":\"bb:00:00:00:00:11\"}'),"
        " ('beta','probe','bb:00:00:00:00:11|HomeNet','HomeNet','',NULL,%lld,%lld,"
        "  '{\"mac\":\"bb:00:00:00:00:11\"}'),"
        " ('gamma','probe','bb:00:00:00:00:11|CafeFree','CafeFree','',NULL,%lld,%lld,"
        "  '{\"mac\":\"bb:00:00:00:00:11\"}'),"
        " ('beta','probe','bb:00:00:00:00:12|x','x\"},{\"remote\":false,\"ssid\":\"1<script>',"
        "  '',NULL,%lld,%lld,'{\"mac\":\"bb:00:00:00:00:12\"}'),"
        " ('beta','probe','aa:00:00:00:00:09|OldPlace','OldPlace','',NULL,%lld,%lld,"
        "  '{\"mac\":\"aa:00:00:00:00:09\"}'),"
        " ('beta','probe','bb:00:00:00:00:13|','','',NULL,%lld,%lld,"
        "  '{\"mac\":\"bb:00:00:00:00:13\"}'),"
        " ('beta','probe','bb:00:00:00:00:14|AncientNet','AncientNet','',NULL,%lld,%lld,"
        "  '{\"mac\":\"bb:00:00:00:00:14\"}'),"
        " ('old','probe','cc:00:00:00:00:11|Gone','Gone','',NULL,%lld,%lld,"
        "  '{\"mac\":\"cc:00:00:00:00:11\"}');",
        T - 700, T - 60, T - 600, T - 50, T - 500, T - 20, T - 500, T - 25, T - 400, T - 10,
        T - 300, T - 100, T - 200, T - 100, T - 300, T - 15, T - 60 * DY, T - 50 * DY,
        T - 300, T - 5);
    WT_EQ(sql_on(g_store, sql), 0);
}

/* The stations heard probing: the local station a peer also heard gains
 * its sites (one a peer, however many SSIDs), the station only the
 * peers heard follows as a grey row with only what they sent, in the
 * route's order; a station held here (even outside the window), a
 * wildcard, a row outside the window and the peer no longer named are
 * never remote rows. Seen red with the held check answering 0 (aa:09 a
 * remote row), with per_site() bypassed (beta twice in bb:11's) and
 * with read_rows() keeping a probe row that names no SSID (bb:13). */
static void test_probe_clients_merge(void) {
    probes_up();
    int st;
    const char *b = get("/api/probes/clients", "", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "\"count\":1,\"total\":1,\"more\":false,");
    WT_HAS(b, "\"siblings_total\":0,\"presence\":");
    WT_HAS(b, ",\"sites\":[{\"site\":\"gamma\",\"label\":null,\"first_seen\":1792626600,"
              "\"last_seen\":1792627150},{\"site\":\"beta\",\"label\":\"beta-site\","
              "\"first_seen\":1792626500,\"last_seen\":1792627140}]}");
    WT_HAS(b, "{\"mac\":\"bb:00:00:00:00:11\",\"random\":true,\"vendor\":null,\"frames\":null,"
              "\"directed\":null,\"signal\":null,\"channel\":null,\"os\":null,\"phy\":null,"
              "\"first_seen\":1792626700,\"last_seen\":1792627190,\"ssid_count\":2,"
              "\"ssids\":[{\"ssid\":\"CafeFree\",");
    WT_HAS(b, "\"first_seen\":1792626700,\"last_seen\":1792627190},{\"ssid\":\"HomeNet\",");
    WT_HAS(b, "\"ssids_more\":false,\"device\":null,\"assoc\":null,\"remote\":true,"
              "\"site\":\"gamma\",\"site_label\":null,\"sites\":[{\"site\":\"gamma\",\"label\":null,"
              "\"first_seen\":1792626800,\"last_seen\":1792627190},{\"site\":\"beta\","
              "\"label\":\"beta-site\",\"first_seen\":1792626700,\"last_seen\":1792627180}]}");
    WT_EQ(count_of(b, "\"remote\":true"), 2);
    /* beta once in each row's sites (aa:01, bb:11, bb:12), bb:12's
     * "site", and the fleet member's peers. */
    WT_EQ(count_of(b, "\"site\":\"beta\""), 5);
    const char *l1 = strstr(b, "{\"mac\":\"aa:00:00:00:00:01\"");
    const char *r1 = strstr(b, "{\"mac\":\"bb:00:00:00:00:11\"");
    const char *r2 = strstr(b, "{\"mac\":\"bb:00:00:00:00:12\"");
    WT_ASSERT(l1 && r1 && r2 && l1 < r1 && r1 < r2);
    /* A remote row has no presence strip and no siblings of its own. */
    WT_EQ(count_of(b, "\"presence\":"), 1);
    WT_EQ(count_of(b, "\"siblings\":"), 1);
    WT_ASSERT(!strstr(b, "aa:00:00:00:00:09"));
    WT_ASSERT(!strstr(b, "bb:00:00:00:00:13"));
    WT_ASSERT(!strstr(b, "bb:00:00:00:00:14"));
    WT_ASSERT(!strstr(b, "cc:00:00:00:00:11"));
    WT_HAS(b, "\"remote\":2,\"remote_cap\":100,\"remote_more\":false,\"partial\":false,"
              "\"remote_off\":null}}\n");
    /* The hostile SSID, escaped, closing nothing. */
    WT_ASSERT(!strstr(b, "<script>"));
    WT_EQ(count_of(b, "\"remote\":false"), 0);
    /* Everything sloth.db retains: aa:09 is local now, with its site,
     * and bb:14 a remote row; sort=first puts the oldest first, as the
     * route orders its own. */
    b = get("/api/probes/clients", "days=0&sort=first", &st, NULL);
    WT_EQ(st, 200);
    WT_EQ(count_of(b, "\"remote\":true"), 3);
    WT_HAS(b, "{\"mac\":\"aa:00:00:00:00:09\"");
    r1 = strstr(b, "{\"mac\":\"bb:00:00:00:00:11\"");
    const char *r4 = strstr(b, "{\"mac\":\"bb:00:00:00:00:14\"");
    WT_ASSERT(r1 && r4 && r4 < r1);
    b = get("/api/probes/clients", "days=0&sort=ssids", &st, NULL);
    r1 = strstr(b, "{\"mac\":\"bb:00:00:00:00:11\"");
    r4 = strstr(b, "{\"mac\":\"bb:00:00:00:00:14\"");
    WT_ASSERT(r1 && r4 && r1 < r4);
    /* A page that does not end the list carries none. */
    b = get("/api/probes/clients", "days=0&limit=1", &st, NULL);
    WT_HAS(b, "\"more\":true");
    WT_EQ(count_of(b, "\"remote\":true"), 0);
    WT_HAS(b, "\"remote_off\":\"not_last_page\"");
    down();
}

/* The networks asked for: HomeNet (asked for here) gains beta, once,
 * though beta heard two stations ask; CafeFree only the peers heard
 * asked for is a grey row whose counts are null; OldPlace, held here
 * outside the window, is never one. */
static void test_probe_ssids_merge(void) {
    probes_up();
    int st;
    const char *b = get("/api/probes/ssids", "", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "\"count\":2,\"total\":2,\"more\":false,");
    WT_HAS(b, ",\"sites\":[{\"site\":\"beta\",\"label\":\"beta-site\","
              "\"first_seen\":1792626500,\"last_seen\":1792627175}]}");
    WT_HAS(b, "{\"ssid\":\"CafeFree\",");
    WT_HAS(b, "\"clients\":null,\"random\":null,\"first_seen\":1792626600,\"last_seen\":1792627190,"
              "\"aps\":null,\"ap_signal\":null,\"uncommon\":null,\"designated\":null,\"remote\":true,"
              "\"site\":\"gamma\",\"site_label\":null,\"sites\":[{\"site\":\"gamma\",\"label\":null,"
              "\"first_seen\":1792626600,\"last_seen\":1792627190},{\"site\":\"beta\","
              "\"label\":\"beta-site\",\"first_seen\":1792626700,\"last_seen\":1792627180}]}");
    WT_EQ(count_of(b, "\"remote\":true"), 2);
    WT_EQ(count_of(b, "\"ssid\":\"HomeNet\""), 1);
    WT_ASSERT(!strstr(b, "OldPlace"));
    WT_ASSERT(!strstr(b, "Gone"));
    WT_ASSERT(!strstr(b, "AncientNet"));
    WT_ASSERT(!strstr(b, "<script>"));
    WT_EQ(count_of(b, "\"remote\":false"), 0);
    /* sort=ssid: by name among the remote rows too. */
    b = get("/api/probes/ssids", "sort=ssid&days=0", &st, NULL);
    const char *a = strstr(b, "{\"ssid\":\"AncientNet\"");
    const char *c = strstr(b, "{\"ssid\":\"CafeFree\"");
    WT_ASSERT(a && c && a < c);
    WT_HAS(b, "{\"ssid\":\"OldPlace\"");    /* local in this window */
    WT_EQ(count_of(b, "\"ssid\":\"OldPlace\""), 1);
    down();
}

/* fleet=0 is each route's own answer, byte for byte, as is every answer
 * with no peer named; shared and groups, the similarity, are the same
 * bytes with the peers' rows there or not (they are never merged, and
 * take no fleet=). Seen red with route_m5()'s merge made to run for
 * PR_SHARED (a "fleet" member on shared, its bytes changed). */
static void test_probes_local_only(void) {
    probes_up();
    static char a[65536], c[65536];
    static const char *const P[][2] = {
        { "/api/probes/clients", "days=0" }, { "/api/probes/ssids", "days=0" },
        { "/api/probes/shared", "mac=aa:00:00:00:00:01&days=0" },
        { "/api/probes/groups", "days=0" },
    };
    for (size_t i = 0; i < sizeof(P) / sizeof(P[0]); i++) {
        int s1, s2;
        size_t l1 = 0, l2 = 0;
        char q[128];
        snprintf(q, sizeof(q), "%s&fleet=0", P[i][1]);
        const char *x = get(P[i][0], i < 2 ? q : P[i][1], &s1, &l1);
        memcpy(a, x, l1 + 1);
        M4.fleet = NULL;
        const char *y = get(P[i][0], P[i][1], &s2, &l2);
        memcpy(c, y, l2 + 1);
        M4.fleet = &F;
        WT_EQ(s1, 200);
        WT_EQ(s1, s2);
        WT_ASSERT(l1 == l2 && !memcmp(a, c, l1));
        WT_ASSERT(!strstr(a, "\"fleet\":"));
        WT_ASSERT(!strstr(a, "bb:00:00:00:00:1"));
        WT_ASSERT(!strstr(a, "CafeFree"));
        int np = F.npeer;
        F.npeer = 0;
        y = get(P[i][0], P[i][1], &s2, &l2);
        F.npeer = np;
        WT_ASSERT(l1 == l2 && !memcmp(a, y, l1));
    }
    int st;
    const char *b = get("/api/probes/shared", "mac=aa:00:00:00:00:01&fleet=1", &st, NULL);
    WT_EQ(st, 400);
    b = get("/api/probes/clients", "scope=monitor", &st, NULL);
    WT_EQ(st, 200);
    WT_ASSERT(!strstr(b, "\"fleet\":"));
    b = get("/api/probes/ssids", "fleet=x", &st, NULL);
    WT_EQ(st, 400);
    WT_HAS(b, "bad_fleet");
    down();
}

/* At most WEB_FV_REMOTE_MAX remote stations and networks, said. */
static void test_probes_cap(void) {
    probes_up();
    sqlite3 *h = NULL;
    WT_EQ(sqlite3_open(g_store, &h), SQLITE_OK);
    sqlite3_exec(h, "BEGIN", NULL, NULL, NULL);
    for (int i = 0; i < 150; i++) {
        char sql[384];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO peer_sightings (peer,kind,key,label,vendor,rssi,first_seen,"
                 "last_seen,extra) VALUES ('gamma','probe','dd:00:00:00:00:%02x|net-%d',"
                 "'net-%d','',NULL,%lld,%lld,'{\"mac\":\"dd:00:00:00:00:%02x\"}')",
                 i + 1, i, i, T - 9000, T - 9000 + i, i + 1);
        WT_EQ(sqlite3_exec(h, sql, NULL, NULL, NULL), SQLITE_OK);
    }
    sqlite3_exec(h, "COMMIT", NULL, NULL, NULL);
    sqlite3_close(h);
    int st;
    const char *b = get("/api/probes/clients", "", &st, NULL);
    WT_EQ(st, 200);
    WT_EQ(count_of(b, "\"remote\":true"), WEB_FV_REMOTE_MAX);
    WT_HAS(b, "\"remote\":100,\"remote_cap\":100,\"remote_more\":true");
    WT_HAS(b, "{\"mac\":\"aa:00:00:00:00:01\"");
    b = get("/api/probes/ssids", "", &st, NULL);
    WT_EQ(st, 200);
    WT_EQ(count_of(b, "\"remote\":true"), WEB_FV_REMOTE_MAX);
    WT_HAS(b, "\"remote\":100,\"remote_cap\":100,\"remote_more\":true");
    WT_HAS(b, "{\"ssid\":\"HomeNet\"");
    down();
}

/* A station only the peers heard probing has a drawer: the hosts by
 * name and each network each heard it ask for. */
static void test_probe_drawer(void) {
    probes_up();
    int st;
    const char *b = get("/api/device/bb:00:00:00:00:11", "", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "\"record\":null");
    WT_HAS(b, "\"fleet\":{\"remote\":true,\"site\":\"gamma\",\"site_label\":null,"
              "\"note\":\"seen at gamma, beta-site\",\"rows\":[],\"ap_rows\":[],"
              "\"probe_rows\":[{\"site\":\"gamma\",\"label\":null,\"kind\":\"probe\","
              "\"first_seen\":1792626800,\"last_seen\":1792627190,\"ssid\":\"CafeFree\",");
    WT_EQ(count_of(b, "\"kind\":\"probe\""), 3);
    b = get("/api/device/bb:00:00:00:00:12", "", &st, NULL);
    WT_EQ(st, 200);
    WT_ASSERT(!strstr(b, "<script>"));
    WT_HAS(b, "\"note\":\"seen at beta-site\"");
    down();
}

#endif

void run_fleetview_tests(void) {
    WT_RUN(test_take);
    WT_RUN(test_members_are_not_secret);
    WT_RUN(test_page);
#ifdef WITH_SQLITE
    WT_RUN(test_devices_merge);
    WT_RUN(test_devices_filters_and_pages);
    WT_RUN(test_local_only_is_unchanged);
    WT_RUN(test_cap);
    WT_RUN(test_aps_and_ble);
    WT_RUN(test_drawers);
    WT_RUN(test_export_carries_no_peer_row);
    WT_RUN(test_probe_clients_merge);
    WT_RUN(test_probe_ssids_merge);
    WT_RUN(test_probes_local_only);
    WT_RUN(test_probes_cap);
    WT_RUN(test_probe_drawer);
#endif
}
