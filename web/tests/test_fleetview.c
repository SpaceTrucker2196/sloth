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

#include "web_adsb.h"
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
        "remote_more", "remote_off", "partial", "note", "ap_rows", "kind", "probe_rows",
        "alt", "visit_first", "pos_prev", "pos_alt", "host", "site_host", NULL };
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
    WT_HAS(p, "  var FV_SEL = { devices: \"d-sites\", aps: \"w-sites\", ble: \"b-sites\", probes: \"pr-sites\",\n"
              "                 adsb: \"adsb-sites\" };");
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
    /* The ADS-B tab: its choice kept as fleet.adsb and every list asked
     * again; each of its three fetches carries the choice; a grey row
     * from the same mark with nothing only this decoder knows; on the
     * plot a peer's aircraft its last position, grey, named, no track. */
    WT_HAS(p, "<select id=\"adsb-sites\"");
    WT_HAS(p, "    prefSet(\"fleet.adsb\", this.value);\n"
              "    if (window.SlothAdsb) SlothAdsb.refresh();\n");
    WT_HAS(p, "  if (window.SlothAdsb) SlothAdsb.init({ go: go, fvMark: fvMark, fvName: fvName,\n"
              "    fvSplit: fvSplit, fvQuery: fvQuery, stamp: stamp });");
    WT_HAS(p, "  function fvq() { return H && H.fvQuery ? H.fvQuery(\"adsb\") : \"\"; }");
    WT_HAS(p, "    getJSON(\"/api/adsb\" + fvq().replace(/^&/, \"?\")).then(function (j) {");
    WT_HAS(p, "\"&offset=\" + off + (q ? \"&q=\" + encodeURIComponent(q) : \"\") + fvq()).then(function (j) {");
    WT_HAS(p, "    getJSON(\"/api/adsb/aircraft?hex=\" + encodeURIComponent(hex) + \"&days=\" + encodeURIComponent(seenDays()) +\n"
              "            fvq()).then(function (j) {");
    WT_HAS(p, "  function row(a, now) {\n    if (remote(a)) return remoteRow(a, now);\n");
    WT_HAS(p, "    var r = el(\"div\", \"adsbrow dt-row remote\" + (sel === a.hex ? \" on\" : \"\"));\n"
              "    var hx = cell(\"c-hx\", a.hex);\n"
              "    var fm = fvMark(a);\n"
              "    if (fm) hx.appendChild(fm);\n");
    WT_HAS(p, "      if (remote(a)) { body.appendChild(seenRemote(a)); return; }");
    WT_HAS(p, "      if (remote(a)) {\n"
              "        if (!num(a.lat)) return;\n"
              "        var rx = X(a.lon), ry = Y(a.lat);\n"
              "        g.globalAlpha = 1;\n"
              "        g.fillStyle = dim; g.strokeStyle = dim;\n"
              "        g.beginPath(); g.arc(rx, ry, sel === a.hex ? 5 : 3, 0, Math.PI * 2); g.stroke();\n"
              "        g.textAlign = \"left\";\n"
              "        g.fillText(label(a) + \" · \" + fvName(a), rx + 7, ry - 6);\n"
              "        if (ppi) ppi.mark(rx, ry, a.hex);\n"
              "        return;\n"
              "      }\n");
    /* The radar scope (ppi.js): another host's aircraft a grey hollow
     * triangle named by its host, no track, no altitude colour. */
    WT_HAS(p, "        if (remote(a))\n"
              "          return { id: a.hex, lat: a.lat, lon: a.lon, picked: picked, fill: false, shape: \"tri\", heading: a.track,\n"
              "                   color: picked ? hot : dim, textColor: picked ? hot : dim, lines: [label(a), \"+ \" + fvName(a)] };\n");
    WT_HAS(p, "    rows.forEach(function (a) {\n      if (remote(a)) return;\n");
    WT_HAS(p, "      fleetLines(kv, j.fleet);");
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
    WT_HAS(b, "\"sites\":[{\"site\":\"gamma\",\"label\":null,\"host\":null,\"first_seen\":1792626500,"
              "\"last_seen\":1792627150},{\"site\":\"beta\",\"label\":\"beta-site\",\"host\":null,"
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
    WT_HAS(b, ",\"fleet\":{\"peers\":[{\"site\":\"beta\",\"label\":\"beta-site\",\"host\":null},"
              "{\"site\":\"gamma\",\"label\":null,\"host\":null}],\"remote\":3,\"remote_cap\":100,"
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
    /* The first page carries them, however much of the local list is
     * left (a field sensor's last page is a deep offset that times out
     * first); a later page carries none, so none is read twice. */
    b = get("/api/devices", "limit=1", &st, NULL);
    WT_HAS(b, "\"more\":true");
    WT_EQ(count_of(b, "\"remote\":true"), 3);
    WT_HAS(b, "\"remote_off\":null");
    b = get("/api/devices", "limit=1&offset=0", &st, NULL);
    WT_EQ(count_of(b, "\"remote\":true"), 3);
    b = get("/api/devices", "limit=2&offset=2", &st, NULL);
    WT_HAS(b, "\"more\":false");
    WT_EQ(count_of(b, "\"remote\":true"), 0);
    WT_HAS(b, "\"remote_off\":\"not_first_page\"");
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
    WT_HAS(b, "\"sites\":[{\"site\":\"beta\",\"label\":\"beta-site\",\"host\":null,");
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
    WT_HAS(b, "\"fleet\":{\"remote\":true,\"site\":\"beta\",\"site_label\":\"beta-site\",\"site_host\":null,"
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
    WT_HAS(b, "\"rows\":[],\"ap_rows\":[{\"site\":\"gamma\",\"label\":null,\"host\":null,\"kind\":\"ap\",");
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
    web_fleet_src_t src = { .sdb = &SDB, .ble = &B };
    char *body = NULL;
    size_t len = 0;
    int st = 0;
    WT_EQ(web_fleet_export_route(&src, "since=0", T, &body, &len, &st), 0);
    WT_EQ(st, 200);
    WT_ASSERT(body != NULL);
    if (body) {
        char *t = realloc(body, len + 1);
        if (t) { body = t; body[len] = '\0'; }
        /* This site's own rows travel (the AP its radio heard); its
         * devices with no source the radio recorded do not (owner rule
         * 2026-11-12). */
        WT_HAS(body, "{\"type\":\"ap\",\"bssid\":\"0a:00:00:00:00:01\"");
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
    WT_HAS(b, ",\"sites\":[{\"site\":\"gamma\",\"label\":null,\"host\":null,\"first_seen\":1792626600,"
              "\"last_seen\":1792627150},{\"site\":\"beta\",\"label\":\"beta-site\",\"host\":null,"
              "\"first_seen\":1792626500,\"last_seen\":1792627140}]}");
    WT_HAS(b, "{\"mac\":\"bb:00:00:00:00:11\",\"random\":true,\"vendor\":null,\"frames\":null,"
              "\"directed\":null,\"signal\":null,\"channel\":null,\"os\":null,\"phy\":null,"
              "\"first_seen\":1792626700,\"last_seen\":1792627190,\"ssid_count\":2,"
              "\"ssids\":[{\"ssid\":\"CafeFree\",");
    WT_HAS(b, "\"first_seen\":1792626700,\"last_seen\":1792627190},{\"ssid\":\"HomeNet\",");
    WT_HAS(b, "\"ssids_more\":false,\"device\":null,\"assoc\":null,\"remote\":true,"
              "\"site\":\"gamma\",\"site_label\":null,\"site_host\":null,\"sites\":[{\"site\":\"gamma\",\"label\":null,\"host\":null,"
              "\"first_seen\":1792626800,\"last_seen\":1792627190},{\"site\":\"beta\","
              "\"label\":\"beta-site\",\"host\":null,\"first_seen\":1792626700,\"last_seen\":1792627180}]}");
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
    /* The first page carries them though the list goes on; a later
     * page carries none. */
    b = get("/api/probes/clients", "days=0&limit=1", &st, NULL);
    WT_HAS(b, "\"more\":true");
    WT_EQ(count_of(b, "\"remote\":true"), 3);
    b = get("/api/probes/clients", "days=0&limit=1&offset=1", &st, NULL);
    WT_EQ(count_of(b, "\"remote\":true"), 0);
    WT_HAS(b, "\"remote_off\":\"not_first_page\"");
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
    WT_HAS(b, ",\"sites\":[{\"site\":\"beta\",\"label\":\"beta-site\",\"host\":null,"
              "\"first_seen\":1792626500,\"last_seen\":1792627175}]}");
    WT_HAS(b, "{\"ssid\":\"CafeFree\",");
    WT_HAS(b, "\"clients\":null,\"random\":null,\"first_seen\":1792626600,\"last_seen\":1792627190,"
              "\"aps\":null,\"ap_signal\":null,\"uncommon\":null,\"designated\":null,\"remote\":true,"
              "\"site\":\"gamma\",\"site_label\":null,\"site_host\":null,\"sites\":[{\"site\":\"gamma\",\"label\":null,\"host\":null,"
              "\"first_seen\":1792626600,\"last_seen\":1792627190},{\"site\":\"beta\","
              "\"label\":\"beta-site\",\"host\":null,\"first_seen\":1792626700,\"last_seen\":1792627180}]}");
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
    WT_HAS(b, "\"fleet\":{\"remote\":true,\"site\":\"gamma\",\"site_label\":null,\"site_host\":null,"
              "\"note\":\"seen at gamma, beta-site\",\"rows\":[],\"ap_rows\":[],"
              "\"probe_rows\":[{\"site\":\"gamma\",\"label\":null,\"host\":null,\"kind\":\"probe\","
              "\"first_seen\":1792626800,\"last_seen\":1792627190,\"ssid\":\"CafeFree\",");
    WT_EQ(count_of(b, "\"kind\":\"probe\""), 3);
    b = get("/api/device/bb:00:00:00:00:12", "", &st, NULL);
    WT_EQ(st, 200);
    WT_ASSERT(!strstr(b, "<script>"));
    WT_HAS(b, "\"note\":\"seen at beta-site\"");
    down();
}


/* ── the ADS-B tab ───────────────────────────────────────────────────── */

static web_adsb_t A;

static void feed_ac(const char *hex, const char *flight, long long last) {
    static web_jrec_t r;
    char line[1024];
    snprintf(line, sizeof(line),
             "{\"type\":\"adsb_aircraft\",\"ts\":%lld,\"hex\":\"%s\",\"non_icao\":%d,"
             "\"state\":\"live\",\"src\":\"file:/run/readsb/aircraft.json\","
             "\"source_type\":\"adsb_icao\",\"flight\":\"%s\",\"squawk\":\"2201\","
             "\"category\":\"A3\",\"emergency\":\"none\",\"on_ground\":0,\"alt_baro\":34000,"
             "\"alt_band\":16,\"gs\":451.2,\"track\":271.5,\"lat\":10.12345,\"lon\":20.54321,"
             "\"pos_ts\":%lld,\"rssi\":-18.4,\"messages\":2210,\"first_seen\":%lld,"
             "\"last_seen\":%lld}",
             last, hex, hex[0] == '~', flight, last, last - 100, last);
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_adsb_record(&A, &r, 1000);
}

/* This site: the panel lists a1b2c3 and ~00abcd; sloth.db's inventory
 * holds a1b2c3 (an hour ago) and 0d0e0f (nine days ago, outside the
 * inventory's 7 days, gone from the panel). The peers (I7's aircraft
 * lines as web_fleet.c ac_row() stores them): a1b2c3 at beta and gamma;
 * b0b001 at beta only, with a position; 0d0e0f at beta; ~00cc01 at gamma
 * with a hostile callsign; b0b002 at beta three days ago (outside the
 * table's freshness and the 1-day window, inside 7 days); dddd03 from
 * the peer no longer named; a key that is no address. */
static void adsb_up(void) {
    up();
    WT_EQ(web_adsb_init(&A), 0);
    feed_ac("a1b2c3", "TST123", T - 30);
    feed_ac("~00abcd", "EMG7", T - 20);
    H.adsb = &A;
    char sql[4096];
    snprintf(sql, sizeof(sql),
        "INSERT INTO adsb_aircraft VALUES ('a1b2c3',0,%lld,%lld,%lld,2,5,'TST123','2201','A3',"
        "'adsb_icao',0,12000,34000,451.2,-18.4,2210,1);"
        "INSERT INTO adsb_aircraft VALUES ('0d0e0f',0,%lld,%lld,%lld,1,2,'OLD9',NULL,'A1',"
        "'mode_s',0,NULL,NULL,NULL,NULL,NULL,0);"
        "INSERT INTO adsb_sightings (last_seen,hex,heard,flight,squawk,emergency,category,"
        "on_ground,alt_baro,alt_band,gs,track,lat,lon,rssi,messages,source_type)"
        " VALUES (%lld,'a1b2c3',%lld,'TST123','2201','none','A3',0,34000,16,451.2,271.5,"
        "10.12345,20.54321,-18.4,2210,'adsb_icao');",
        T - 7200, T - 3600, T - 5400, T - 10 * DY, T - 9 * DY, T - 10 * DY, T - 3600, T - 3600);
    WT_EQ(sdb_exec(g_db, sql), 0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO peer_sightings (peer,kind,key,label,vendor,rssi,first_seen,last_seen,extra)"
        " VALUES"
        " ('beta','aircraft','a1b2c3','TST123','A3',-20,%lld,%lld,"
        "  '{\"visit_first\":%lld,\"squawk\":\"2201\",\"emergency\":\"none\",\"on_ground\":false,"
        "\"alt\":34000}'),"
        " ('gamma','aircraft','a1b2c3','TST123','A3',-25,%lld,%lld,'{\"on_ground\":false}'),"
        " ('beta','aircraft','b0b001','PEER1','A1',-21,%lld,%lld,"
        "  '{\"visit_first\":%lld,\"squawk\":\"1200\",\"emergency\":\"none\",\"on_ground\":false,"
        "\"alt\":4500,\"gs\":120.5,\"track\":90.0,\"rssi\":-21.3,\"messages\":77,"
        "\"lat\":10.50000,\"lon\":20.25000,\"pos_ts\":%lld,\"pos_prev\":%lld,\"pos_alt\":4400}'),"
        " ('beta','aircraft','0d0e0f','OLD9','A1',NULL,%lld,%lld,'{\"on_ground\":false}'),"
        " ('gamma','aircraft','~00cc01','<b>\"x','A7',NULL,%lld,%lld,"
        "  '{\"squawk\":\"7700\",\"emergency\":\"general\",\"on_ground\":true}'),"
        " ('beta','aircraft','b0b002','STALE2','',NULL,%lld,%lld,'{\"on_ground\":false}'),"
        " ('old','aircraft','dddd03','GONE','',NULL,%lld,%lld,'{}'),"
        " ('beta','aircraft','NOTHEX','BAD','',NULL,%lld,%lld,'{}');",
        T - 900, T - 40, T - 900, T - 800, T - 45,
        T - 600, T - 10, T - 600, T - 15, T - 60,
        T - 500, T - 100, T - 400, T - 50,
        T - 3 * DY - 100, T - 3 * DY, T - 300, T - 10, T - 300, T - 10);
    WT_EQ(sql_on(g_store, sql), 0);
}

static void adsb_down(void) {
    H.adsb = NULL;
    web_adsb_destroy(&A);
    down();
}

/* The panel's table: the local rows as they were, a1b2c3 with each
 * peer's site; the peers' fresh aircraft after them, grey, only what
 * their lines held; 0d0e0f is not in the panel, so a peer's row of it is
 * remote here; b0b002 too old for a table of now; the counts the
 * panel's own. The panel check in held_here() cannot be isolated here:
 * every address the panel holds is on its one page, so it is matched as
 * a local row first; the inventory test below carries that guard. */
static void test_adsb_merge(void) {
    adsb_up();
    int st;
    const char *b = get("/api/adsb", "", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "\"total\":2,\"live\":2,\"with_pos\":2,\"emergency\":0,\"rows\":[");
    WT_HAS(b, "\"sites\":[{\"site\":\"beta\",\"label\":\"beta-site\",\"host\":null,\"first_seen\":1792626300,"
              "\"last_seen\":1792627160},{\"site\":\"gamma\",\"label\":null,\"host\":null,"
              "\"first_seen\":1792626400,\"last_seen\":1792627155}]}");
    WT_HAS(b, "{\"hex\":\"b0b001\",\"non_icao\":0,\"flight\":\"PEER1\",\"squawk\":\"1200\","
              "\"category\":\"A1\",\"emergency\":\"none\",\"on_ground\":0,\"alt\":4500,"
              "\"gs\":120.5,\"track\":90.0,\"lat\":10.50000,\"lon\":20.25000,"
              "\"pos_ts\":1792627185,\"rssi\":-21.3,\"messages\":77,\"first_seen\":1792626600,"
              "\"last_seen\":1792627190,\"remote\":true,\"site\":\"beta\","
              "\"site_label\":\"beta-site\",\"site_host\":null,\"sites\":[");
    WT_EQ(count_of(b, "\"remote\":true"), 3);
    WT_HAS(b, "{\"hex\":\"0d0e0f\",");
    WT_HAS(b, "{\"hex\":\"~00cc01\",\"non_icao\":1,");
    WT_ASSERT(!strstr(b, "b0b002"));
    WT_ASSERT(!strstr(b, "dddd03"));
    WT_ASSERT(!strstr(b, "NOTHEX"));
    WT_EQ(count_of(b, "\"hex\":\"a1b2c3\""), 1);
    /* A remote row claims nothing only this decoder knows. */
    const char *r1 = strstr(b, "{\"hex\":\"b0b001\"");
    WT_ASSERT(r1 && !strstr(r1, "\"track_pts\"") && !strstr(r1, "\"state\"") &&
              !strstr(r1, "\"alt_baro\"") && !strstr(r1, "\"alert\""));
    /* After every local row. */
    const char *l2 = strstr(b, "{\"hex\":\"~00abcd\"");
    WT_ASSERT(l2 && r1 && l2 < r1);
    WT_HAS(b, ",\"fleet\":{\"peers\":[{\"site\":\"beta\",\"label\":\"beta-site\",\"host\":null},"
              "{\"site\":\"gamma\",\"label\":null,\"host\":null}],\"remote\":3,\"remote_cap\":100,"
              "\"remote_more\":false,\"partial\":false,\"remote_off\":null}}");
    /* The hostile callsign, escaped. */
    WT_ASSERT(!strstr(b, "<b>"));
    WT_HAS(b, "\"flight\":\"\\u003cb\\u003e\\\"x\"");
    /* /api/adsb pages nothing: a table limit= cut still carries them. */
    b = get("/api/adsb", "limit=1", &st, NULL);
    WT_EQ(st, 200);
    WT_EQ(count_of(b, "\"remote\":true"), 3);
    WT_HAS(b, "\"remote_off\":null");
    adsb_down();
}

/* The inventory: sloth.db's rows over days=, the peers' addresses
 * neither sloth.db nor the panel holds after them; 0d0e0f is held
 * (sloth.db, outside the window) so never remote. q a hex or callsign
 * prefix, any case. ~00abcd is the panel's and not yet sloth.db's: held,
 * never remote. Seen red with held_here() skipping sloth.db (0d0e0f then
 * a remote row) and with it skipping the panel (~00abcd then one). */
static void test_adsb_seen_merge(void) {
    adsb_up();
    WT_EQ(sql_on(g_store, "INSERT INTO peer_sightings (peer,kind,key,label,vendor,rssi,"
                          "first_seen,last_seen,extra) VALUES ('beta','aircraft','~00abcd',"
                          "'EMG7','A1',NULL,1792627000,1792627100,'{}')"), 0);
    int st;
    const char *b = get("/api/adsb/seen", "", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "\"total\":1,\"more\":false");
    WT_HAS(b, "{\"hex\":\"a1b2c3\",");
    WT_HAS(b, "\"sites\":[{\"site\":\"beta\",");
    WT_HAS(b, "{\"hex\":\"b0b001\",\"non_icao\":0,\"first_seen\":1792626600,"
              "\"last_seen\":1792627190,\"flight\":\"PEER1\",\"squawk\":\"1200\","
              "\"category\":\"A1\",\"alt\":4500,\"messages\":77,\"remote\":true,");
    WT_HAS(b, "{\"hex\":\"b0b002\",");
    WT_HAS(b, "{\"hex\":\"~00cc01\",");
    WT_ASSERT(!strstr(b, "0d0e0f"));
    WT_ASSERT(!strstr(b, "~00abcd"));
    WT_EQ(count_of(b, "\"remote\":true"), 3);
    const char *r1 = strstr(b, "{\"hex\":\"b0b001\"");
    WT_ASSERT(r1 && !strstr(r1, "\"visits\"") && !strstr(r1, "\"alt_max\"") &&
              !strstr(r1, "\"lat\""));
    b = get("/api/adsb/seen", "days=1", &st, NULL);
    WT_ASSERT(!strstr(b, "b0b002"));
    WT_EQ(count_of(b, "\"remote\":true"), 2);
    b = get("/api/adsb/seen", "q=B0B", &st, NULL);
    WT_EQ(count_of(b, "\"remote\":true"), 2);
    WT_ASSERT(!strstr(b, "~00cc01"));
    b = get("/api/adsb/seen", "q=peer", &st, NULL);
    WT_EQ(count_of(b, "\"remote\":true"), 1);
    WT_HAS(b, "\"b0b001\"");
    adsb_down();
}

/* fleet=0 is each ADS-B route's own answer byte for byte, as is no peer
 * configured; nothing merges under Monitor. */
static void test_adsb_local_only(void) {
    adsb_up();
    static char a[65536], c[65536];
    static const char *const P[][2] = {
        { "/api/adsb", "" }, { "/api/adsb", "limit=1" }, { "/api/adsb/seen", "" },
        { "/api/adsb/aircraft", "hex=b0b001" }, { "/api/adsb/aircraft", "hex=a1b2c3" },
    };
    for (size_t i = 0; i < sizeof(P) / sizeof(P[0]); i++) {
        int s1, s2;
        size_t l1 = 0, l2 = 0;
        char q[128];
        snprintf(q, sizeof(q), "%s%sfleet=0", P[i][1], P[i][1][0] ? "&" : "");
        const char *x = get(P[i][0], q, &s1, &l1);
        memcpy(a, x, l1 + 1);
        M4.fleet = NULL;
        const char *y = get(P[i][0], P[i][1], &s2, &l2);
        memcpy(c, y, l2 + 1);
        M4.fleet = &F;
        WT_EQ(s1, 200);
        WT_EQ(s1, s2);
        WT_ASSERT(l1 == l2 && !memcmp(a, c, l1));
        WT_ASSERT(!strstr(a, "\"fleet\":"));
        int np = F.npeer;
        F.npeer = 0;
        y = get(P[i][0], P[i][1], &s2, &l2);
        F.npeer = np;
        WT_ASSERT(l1 == l2 && !memcmp(a, y, l1));
    }
    int st;
    const char *b = get("/api/adsb", "scope=monitor", &st, NULL);
    WT_EQ(st, 200);
    WT_ASSERT(!strstr(b, "\"fleet\":"));
    b = get("/api/adsb", "fleet=2", &st, NULL);
    WT_EQ(st, 400);
    WT_HAS(b, "bad_fleet");
    adsb_down();
}

/* At most WEB_FV_REMOTE_MAX remote aircraft, said. */
static void test_adsb_cap(void) {
    adsb_up();
    sqlite3 *h = NULL;
    WT_EQ(sqlite3_open(g_store, &h), SQLITE_OK);
    sqlite3_exec(h, "BEGIN", NULL, NULL, NULL);
    for (int i = 0; i < 150; i++) {
        char sql[256];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO peer_sightings (peer,kind,key,label,vendor,rssi,first_seen,"
                 "last_seen,extra) VALUES ('gamma','aircraft','e0%04x','','',NULL,%lld,%lld,"
                 "'{\"on_ground\":false}')", i, T - 400, T - 300 + i);
        WT_EQ(sqlite3_exec(h, sql, NULL, NULL, NULL), SQLITE_OK);
    }
    sqlite3_exec(h, "COMMIT", NULL, NULL, NULL);
    sqlite3_close(h);
    int st;
    const char *b = get("/api/adsb", "", &st, NULL);
    WT_EQ(st, 200);
    WT_EQ(count_of(b, "\"remote\":true"), WEB_FV_REMOTE_MAX);
    WT_HAS(b, "\"remote\":100,\"remote_cap\":100,\"remote_more\":true");
    WT_EQ(count_of(b, "\"hex\":\"a1b2c3\""), 1);
    WT_EQ(count_of(b, "\"hex\":\"~00abcd\""), 1);
    b = get("/api/adsb/seen", "", &st, NULL);
    WT_EQ(st, 200);
    WT_EQ(count_of(b, "\"remote\":true"), WEB_FV_REMOTE_MAX);
    WT_HAS(b, "\"remote_more\":true");
    adsb_down();
}

/* The detail: an address only a peer heard answers 200 with each
 * host's row and the note naming them; its sightings stay this site's
 * (none). One this site holds says remote false; one nobody heard is
 * the route's own answer. Seen red with the panel check removed from
 * web_fv_aircraft() (~00abcd, the panel's only, then read remote). */
static void test_adsb_detail(void) {
    adsb_up();
    int st;
    const char *b = get("/api/adsb/aircraft", "hex=b0b001", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "\"aircraft\":null");
    WT_HAS(b, "\"sightings\":[]");
    WT_HAS(b, "\"fleet\":{\"remote\":true,\"site\":\"beta\",\"site_label\":\"beta-site\",\"site_host\":null,"
              "\"note\":\"seen at beta-site\",\"rows\":[{\"site\":\"beta\",\"label\":\"beta-site\",\"host\":null,"
              "\"kind\":\"aircraft\",\"first_seen\":1792626600,\"last_seen\":1792627190,"
              "\"visit_first\":1792626600,\"flight\":\"PEER1\",\"squawk\":\"1200\","
              "\"category\":\"A1\",\"emergency\":\"none\",\"on_ground\":false,\"alt\":4500,"
              "\"gs\":120.5,\"track\":90.0,\"rssi\":-21.3,\"messages\":77,\"lat\":10.50000,"
              "\"lon\":20.25000,\"pos_ts\":1792627185,\"pos_prev\":1792627140,\"pos_alt\":4400}]}");
    WT_ASSERT(!strstr(b, "not heard"));
    b = get("/api/adsb/aircraft", "hex=a1b2c3", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "\"fleet\":{\"remote\":false,");
    WT_HAS(b, "\"note\":null");
    WT_EQ(count_of(b, "\"kind\":\"aircraft\""), 2);
    b = get("/api/adsb/aircraft", "hex=~00cc01", &st, NULL);
    WT_EQ(st, 200);
    WT_HAS(b, "\"note\":\"seen at gamma\"");
    WT_ASSERT(!strstr(b, "<b>"));
    /* Held in sloth.db only (gone from the panel): not remote. */
    b = get("/api/adsb/aircraft", "hex=0d0e0f", &st, NULL);
    WT_HAS(b, "\"fleet\":{\"remote\":false,");
    b = get("/api/adsb/aircraft", "hex=eeeeee", &st, NULL);
    WT_EQ(st, 200);
    WT_ASSERT(!strstr(b, "\"fleet\""));
    /* The panel's own (not in sloth.db yet) is this site's too. */
    sql_on(g_store, "INSERT INTO peer_sightings (peer,kind,key,label,vendor,rssi,first_seen,"
                    "last_seen,extra) VALUES ('beta','aircraft','~00abcd','EMG7','A1',NULL,"
                    "1792627000,1792627100,'{}')");
    b = get("/api/adsb/aircraft", "hex=~00abcd", &st, NULL);
    WT_HAS(b, "\"aircraft\":null");
    WT_HAS(b, "\"fleet\":{\"remote\":false,");
    adsb_down();
}

/* The export's aircraft are sloth.db's, never a peer's. Seen red with a
 * peer's address inserted into sloth.db's adsb_aircraft. */
static void test_export_carries_no_peer_aircraft(void) {
    adsb_up();
    web_fleet_src_t src = { .sdb = &SDB, .ble = &B, .adsb = &A };
    char *body = NULL;
    size_t len = 0;
    int st = 0;
    WT_EQ(web_fleet_export_route(&src, "since=0&gnss=1&adsb=1", T, &body, &len, &st), 0);
    WT_EQ(st, 200);
    WT_ASSERT(body != NULL);
    if (body) {
        char *t = realloc(body, len + 1);
        if (t) { body = t; body[len] = '\0'; }
        WT_HAS(body, "{\"type\":\"aircraft\",\"hex\":\"a1b2c3\"");
        WT_ASSERT(!strstr(body, "b0b001"));
        WT_ASSERT(!strstr(body, "~00cc01"));
        WT_ASSERT(!strstr(body, "PEER1"));
        free(body);
    }
    adsb_down();
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
    WT_RUN(test_adsb_merge);
    WT_RUN(test_adsb_seen_merge);
    WT_RUN(test_adsb_local_only);
    WT_RUN(test_adsb_cap);
    WT_RUN(test_adsb_detail);
    WT_RUN(test_export_carries_no_peer_aircraft);
#endif
}
