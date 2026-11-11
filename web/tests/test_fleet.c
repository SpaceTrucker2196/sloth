/* The owner's fleet (#192 F1, web_fleet.h; ADR 0008): the peer URL
 * rule, the member allow-list held to web_secret.h, the export over a
 * sloth.db generated from sloth's own DDL with a credential, a
 * username, EAPOL rows and a RADIUS identity seeded and held out of it,
 * `since`, and the pull from a loopback server answering canned bytes:
 * a good answer stored and widened by a second, and every refused
 * answer (oversize, cut short, malformed, an unknown member, a wrong
 * count, no end line, a non-200) leaving every sighting as it was. The
 * v7 -> v8 migration and its failure are test_store.c's, beside the
 * other steps (make_v6() lives there). */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "web_assets.h"
#include "web_config.h"
#include "web_fleet.h"
#include "web_frrs.h"
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

/* ── the peer list ──────────────────────────────────────────────────── */

/* Seen red with web_fleet_in_tailnet() testing the second octet against
 * 0x80 (100.128.0.0 then taken as the tailnet) and with the port's
 * range check dropped (":0" taken). */
static void test_peer_urls(void) {
    web_fleet_peer_cfg_t p;
    char err[200];
    WT_EQ(web_fleet_parse_peer("w9fjc=http://100.64.1.2:8770", &p, err, sizeof(err)), 0);
    WT_ASSERT(!strcmp(p.name, "w9fjc"));
    WT_ASSERT(!strcmp(p.url, "http://100.64.1.2:8770"));
    WT_EQ(p.port, 8770);
    WT_EQ(web_fleet_check_peer(&p, 0, err, sizeof(err)), 0);
    WT_EQ(web_fleet_parse_peer("beta-site=http://100.127.255.254/", &p, err, sizeof(err)), 0);
    WT_EQ(p.port, 80);
    WT_ASSERT(!strcmp(p.url, "http://100.127.255.254:80"));
    WT_EQ(web_fleet_check_peer(&p, 0, err, sizeof(err)), 0);
    /* Routable, and the edges of 100.64.0.0/10: refused unless forced. */
    static const char *const outside[] = {
        "x=http://8.8.8.8:8770", "x=http://100.63.255.255:8770",
        "x=http://100.128.0.1:8770", "x=http://127.0.0.1:8770",
        "x=http://192.168.1.10:8770",
    };
    for (size_t i = 0; i < sizeof(outside) / sizeof(outside[0]); i++) {
        WT_EQ(web_fleet_parse_peer(outside[i], &p, err, sizeof(err)), 0);
        WT_EQ(web_fleet_check_peer(&p, 0, err, sizeof(err)), -1);
        WT_HAS(err, "outside the tailnet");
        WT_EQ(web_fleet_check_peer(&p, 1, err, sizeof(err)), 0);
    }
    static const char *const bad[] = {
        "nourl", "=http://100.64.0.1", "bad name=http://100.64.0.1",
        "x=https://100.64.0.1", "x=http://host.example:80", "x=http://100.64.0.1:0",
        "x=http://100.64.0.1:70000", "x=http://100.64.0.1/api/fleet/export",
        "x=http://100.64.0.1:80x", "x=http://100.64.0.1:", "x=http://[::1]:80",
        "x=http://100.64.0.1.5:80", "x=", "x=http://",
        "a234567890123456789012345678901234=http://100.64.0.1",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int rc = web_fleet_parse_peer(bad[i], &p, err, sizeof(err));
        if (rc != -1) fprintf(stderr, "    taken: %s\n", bad[i]);
        WT_EQ(rc, -1);
    }
}

typedef struct {
    web_config_t cfg;
    int          rc;
    char        *err, *ann;
} parsed_t;

static void parse(parsed_t *p, const char *const *args) {
    char *argv[24];
    int argc = 0;
    argv[argc++] = (char *)"slothweb";
    for (int i = 0; args[i] && argc < 23; i++) argv[argc++] = (char *)args[i];
    argv[argc] = NULL;
    char *out = NULL;
    size_t ol = 0, el = 0, al = 0;
    p->err = p->ann = NULL;
    FILE *o = open_memstream(&out, &ol);
    FILE *e = open_memstream(&p->err, &el);
    p->rc = web_config_parse(&p->cfg, argc, argv, o, e);
    fclose(o);
    fclose(e);
    free(out);
    FILE *a = open_memstream(&p->ann, &al);
    if (p->rc == 0) web_config_announce(&p->cfg, a);
    fclose(a);
}

static void done(parsed_t *p) {
    free(p->err);
    free(p->ann);
}

/* The flags. A tailnet peer is quiet; one outside is refused, and with
 * the flag announced; --strict refuses any. */
static void test_peer_flags(void) {
    parsed_t p;
#ifdef WITH_SQLITE
    static const char *const one[] = { "--peer", "lab=http://100.80.0.9:8770",
                                       "--peer-interval-secs", "30", NULL };
    parse(&p, one);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.npeer, 1);
    WT_EQ(p.cfg.peer_interval_s, 30);
    WT_LACKS(p.ann, "--peer");
    done(&p);
    static const char *const out[] = { "--peer", "x=http://192.0.2.7:8770", NULL };
    parse(&p, out);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--peer x: http://192.0.2.7:8770 is outside the tailnet");
    done(&p);
    /* The flag after the peer: the rule is applied to the whole line. */
    static const char *const forced[] = { "--peer", "x=http://192.0.2.7:8770",
                                          "--peer-allow-outside-tailnet", NULL };
    parse(&p, forced);
    WT_EQ(p.rc, 0);
    WT_HAS(p.ann, "WARNING: --peer x at http://192.0.2.7:8770 is outside the tailnet");
    done(&p);
    static const char *const strict[] = { "--peer", "lab=http://100.80.0.9", "--strict", NULL };
    parse(&p, strict);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--strict refuses --peer.");
    done(&p);
    static const char *const twice[] = { "--peer", "a=http://100.80.0.9", "--peer",
                                         "a=http://100.80.0.10", NULL };
    parse(&p, twice);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "given twice");
    done(&p);
    static const char *const many[] = {
        "--peer", "a=http://100.80.0.1", "--peer", "b=http://100.80.0.2",
        "--peer", "c=http://100.80.0.3", "--peer", "d=http://100.80.0.4",
        "--peer", "e=http://100.80.0.5", "--peer", "f=http://100.80.0.6",
        "--peer", "g=http://100.80.0.7", "--peer", "h=http://100.80.0.8",
        "--peer", "i=http://100.80.0.9", NULL };
    parse(&p, many);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--peer: at most 8 peers");
    done(&p);
#else
    static const char *const one[] = { "--peer", "lab=http://100.80.0.9:8770", NULL };
    parse(&p, one);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--peer needs SQLite");
    done(&p);
#endif
    static const char *const iv[] = { "--peer-interval-secs", "5", NULL };
    parse(&p, iv);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "want a whole number from 10 to 3600");
    done(&p);
    static const char *const none[] = { NULL };
    parse(&p, none);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.npeer, 0);
    WT_EQ(p.cfg.peer_interval_s, WEB_FLEET_INTERVAL_DEF);
    done(&p);
}

/* Every member a fleet line may carry is a name web_secret.h does not
 * withhold; the positive control is a name it does. Seen red with
 * "username" added to the wifi line's members. */
static void test_members_are_not_secret(void) {
    int names = 0;
    for (size_t i = 0; i < web_fleet_members_n; i++) {
        const char *const *m = web_fleet_members[i];
        WT_ASSERT(web_fleet_members_of(m[0]) == m);
        for (int k = 1; m[k]; k++) {
            names++;
            if (web_sdb_is_secret("fleet", m[k], "TEXT"))
                fprintf(stderr, "    %s.%s is a withheld name\n", m[0], m[k]);
            WT_ASSERT(!web_sdb_is_secret("fleet", m[k], "TEXT"));
        }
    }
    WT_ASSERT(names > 50);
    WT_ASSERT(web_sdb_is_secret("fleet", "username", "TEXT"));
    WT_ASSERT(web_sdb_is_secret("fleet", "pmkid", "TEXT"));
    WT_ASSERT(web_fleet_members_of("eapol") == NULL);
    WT_ASSERT(web_fleet_members_of("cleartext_creds") == NULL);
}

/* The haversine against values worked by hand: a degree of longitude on
 * the equator, and W9FJC to Chicago. */
static void test_distance(void) {
    double d = web_fleet_dist_m(0, 0, 0, 1);
    WT_ASSERT(d > 111195.0 && d < 111195.2);
    d = web_fleet_dist_m(33.32919, -111.87007, 41.8781136, -87.6297982);
    WT_ASSERT(d > 2326924.5 && d < 2326925.5);
    WT_ASSERT(web_fleet_dist_m(33.32919, -111.87007, 33.32919, -111.87007) == 0);
}


/* ── the Fleet tab's page (web/ui/fleet.js) ─────────────────────────── */

/* The module's own text: its header comment to its export line. */
static char *fleet_module(const char *p) {
    const char *s = strstr(p, "// slothweb: the Fleet view");
    const char *m = strstr(p, "window.SlothFleet = { init: init, show: show };");
    if (!s || !m || s >= m) return NULL;
    size_t n = (size_t)(m - s);
    char *mod = malloc(n + 1);
    if (!mod) return NULL;
    memcpy(mod, s, n);
    mod[n] = '\0';
    return mod;
}

static int count_of(const char *s, const char *needle) {
    int n = 0;
    for (const char *q = strstr(s, needle); q; q = strstr(q + 1, needle)) n++;
    return n;
}

/* The tab after TACDB, its click, show()'s hook, the init line with the
 * helpers lent, the view and its ids; the map is the page's own <svg>
 * drawn with the elements' length properties (no attribute writes, no
 * namespace URL in the page); the module fetches nothing but the two
 * routes. Pinned by whole functions (#171 V1's review): the projection,
 * a site's bar on the shared axis, the device link, the SVG element
 * maker, the poll. The fetch census was seen red with a third getJSON
 * ("/api/fleet/peers") added to loadOverview(), and with a fetch("/x")
 * added to load(); the one-control census with a second <select
 * id="fleet-x"> added to v-fleet; the token-only colours with the
 * self mark's fill written as #ff8c26. */
static void test_fleet_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "<li><button type=\"button\" class=\"go\" id=\"nav-tacdb\">TACDB</button></li>\n"
              "      <li><button type=\"button\" class=\"go\" id=\"nav-fleet\">Fleet</button></li>");
    WT_HAS(p, "  $(\"nav-fleet\").addEventListener(\"click\", function () { show(\"fleet\"); });");
    WT_HAS(p, "    if (v === \"fleet\" && window.SlothFleet) SlothFleet.show();");
    WT_HAS(p, "  if (window.SlothFleet) SlothFleet.init({ el: el, set: set, getJSON: getJSON, errText: errText,\n"
              "    stamp: stamp, openDrawer: openDrawer, openBleDrawer: openBleDrawer });");
    WT_HAS(p, "\"aprs\", \"radar\", \"fleet\"];");
    WT_HAS(p, "<div id=\"v-fleet\" hidden>");
    WT_HAS(p, "<svg id=\"fleet-map\" viewBox=\"0 0 600 300\" role=\"img\" aria-label=");
    WT_HAS(p, "<g id=\"fleet-map-g\"></g></svg>");
    static const char *const ids[] = {
        "fleet-head", "fleet-empty", "fleet-map", "fleet-map-g", "fleet-map-note",
        "fleet-cards", "fleet-shared-note", "fleet-kind", "fleet-shared-rows", "fleet-axis",
    };
    char *mod = fleet_module(p);
    WT_ASSERT(mod != NULL);
    if (!mod) return;
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        char want[64];
        snprintf(want, sizeof(want), " id=\"%s\"", ids[i]);
        WT_HAS(p, want);
        snprintf(want, sizeof(want), "\"%s\"", ids[i]);
        WT_HAS(mod, want);
    }
    /* The whole functions. */
    WT_HAS(mod,
              "  function project(pts) {\n"
              "    var lat0 = 0, i;\n"
              "    for (i = 0; i < pts.length; i++) lat0 += pts[i].lat / pts.length;\n"
              "    var k = Math.cos(lat0 * Math.PI / 180);\n"
              "    var x0 = Infinity, x1 = -Infinity, y0 = Infinity, y1 = -Infinity;\n"
              "    for (i = 0; i < pts.length; i++) {\n"
              "      var x = pts[i].lon * k, y = -pts[i].lat;\n"
              "      x0 = Math.min(x0, x); x1 = Math.max(x1, x); y0 = Math.min(y0, y); y1 = Math.max(y1, y);\n"
              "    }\n"
              "    var sx = x1 - x0, sy = y1 - y0;\n"
              "    var sc = Math.min(sx > 0 ? (MAP_W - 2 * PAD) / sx : Infinity, sy > 0 ? (MAP_H - 2 * PAD) / sy : Infinity);\n"
              "    if (!isFinite(sc)) sc = 0;\n"
              "    var cx = (x0 + x1) / 2, cy = (y0 + y1) / 2;\n"
              "    return function (lat, lon) {\n"
              "      return [MAP_W / 2 + (lon * k - cx) * sc, MAP_H / 2 + (-lat - cy) * sc];\n"
              "    };\n"
              "  }");
    WT_HAS(mod,
              "  function lane(site, t0, t1) {\n"
              "    var ln = H.el(\"div\", \"fleet-lane\" + (site.site === \"self\" ? \" self\" : \"\"));\n"
              "    ln.appendChild(H.el(\"span\", \"fleet-who\", site.site === \"self\" ? \"here\" : site.site));\n"
              "    var tr = H.el(\"div\", \"fleet-track\"), b = H.el(\"div\", \"fleet-bar\");\n"
              "    var span = t1 > t0 ? t1 - t0 : 1;\n"
              "    var a = Math.max(0, (site.first_seen - t0) / span), z = Math.min(1, (site.last_seen - t0) / span);\n"
              "    b.style.left = (a * 100).toFixed(2) + \"%\";\n"
              "    b.style.width = (Math.max(0, z - a) * 100).toFixed(2) + \"%\";\n"
              "    b.title = H.stamp(site.first_seen) + \" to \" + H.stamp(site.last_seen) +\n"
              "              (num(site.rssi) ? \", \" + site.rssi + \" dBm\" : \"\");\n"
              "    tr.appendChild(b);\n"
              "    ln.appendChild(tr);\n"
              "    return ln;\n"
              "  }");
    WT_HAS(mod,
              "  function devLink(kind, r) {\n"
              "    var b = H.el(\"button\", \"fleet-dev\", r.key);\n"
              "    b.type = \"button\";\n"
              "    b.title = \"open \" + r.addr;\n"
              "    b.addEventListener(\"click\", function () {\n"
              "      if (kind === \"ble\") H.openBleDrawer(r.addr);\n"
              "      else H.openDrawer(r.addr);\n"
              "    });\n"
              "    return b;\n"
              "  }");
    WT_HAS(mod,
              "  function svgEl(tag, cls) {\n"
              "    var e = document.createElementNS($(\"fleet-map\").namespaceURI, tag);\n"
              "    if (cls) e.classList.add(cls);\n"
              "    return e;\n"
              "  }");
    WT_HAS(mod,
              "    function sized(t, px) { t.style.fontSize = (px * fk).toFixed(1) + \"px\"; return t; }");
    WT_HAS(mod,
              "      kv(dl, \"backfill\", p.pages_refused ? \"not offered: the peer's build has no paged export (F1); upgrade it\"\n"
              "                         : bf.length ? \"fetching the rest of \" + bf.join(\", \") + \" (\" + p.pages + \" pages, \" +\n"
              "                          p.page_failures + \" refused)\" : \"complete\" + (p.pages ? \" (\" + p.pages + \" pages)\" : \"\"),\n"
              "         p.page_failures > 0 || !!p.pages_refused);");
    WT_HAS(mod,
              "  function show() {\n"
              "    load();\n"
              "    if (!S.timer) S.timer = setInterval(function () { if (!$(\"v-fleet\").hidden) load(); }, POLL_MS);\n"
              "  }");
    /* The module's fetches: the two routes, through the page's getJSON,
     * and nothing else. */
    WT_EQ(count_of(mod, "getJSON("), 2);
    WT_HAS(mod, "H.getJSON(\"/api/fleet/overview\")");
    WT_HAS(mod, "H.getJSON(\"/api/fleet/shared?kind=\" + kind + \"&limit=100\")");
    WT_LACKS(mod, "fetch(");
    WT_LACKS(mod, "XMLHttpRequest");
    WT_LACKS(mod, "<canvas");
    /* The view: one control (kept, test_prefs.c), one SVG, no canvas. */
    const char *v = strstr(p, "<div id=\"v-fleet\" hidden>");
    const char *ve = v ? strstr(v, "<div id=\"v-tacdb\" hidden>") : NULL;
    WT_ASSERT(v && ve);
    if (v && ve) {
        size_t n = (size_t)(ve - v);
        char *view = malloc(n + 1);
        if (view) {
            memcpy(view, v, n);
            view[n] = '\0';
            WT_EQ(count_of(view, "<select"), 1);
            WT_EQ(count_of(view, "<svg"), 1);
            WT_EQ(count_of(view, "<canvas"), 0);
            WT_LACKS(view, "<input");
            free(view);
        }
    }
    /* The stylesheet after radar's, the script after radar.js. */
    const char *rcss = strstr(p, ".radar-stage { position: relative;"), *fcss = strstr(p, "#fleet-map { display: block;");
    WT_ASSERT(rcss && fcss && rcss < fcss);
    const char *rjs = strstr(p, "// slothweb: the Radar view"), *fjs = strstr(p, "// slothweb: the Fleet view");
    WT_ASSERT(rjs && fjs && rjs < fjs);
    /* Colours by token only, so the light theme follows. */
    const char *c0 = fcss, *c1 = fcss ? strstr(fcss, ".fleet-lane.self .fleet-bar") : NULL;
    WT_ASSERT(c0 && c1);
    if (c0 && c1) {
        size_t n = (size_t)(c1 - c0);
        char *css = malloc(n + 1);
        if (css) {
            memcpy(css, c0, n);
            css[n] = '\0';
            WT_LACKS(css, ": #");
            WT_LACKS(css, "rgb(");
            WT_LACKS(css, "hsl(");
            free(css);
        }
    }
    free(mod);
}

#ifdef WITH_SQLITE

#define T SDB_NOW
#define HR 3600LL
#define DY 86400LL

static char g_dir[TEST_TMP_MAX];
static char g_db[TEST_TMP_MAX + 32], g_store[TEST_TMP_MAX + 32];
static web_store_t   S;
static web_slothdb_t SDB;
static web_frrs_t    FR;

static void rm_dir(void) {
    static const char *const names[] = {
        "sloth.db", "sloth.db-wal", "sloth.db-shm", "sloth.db-journal",
        "slothweb.db", "slothweb.db-wal", "slothweb.db-shm", "slothweb.db-journal",
        "here.db", "here.db-wal", "here.db-shm", "here.db-journal",
        "here-web.db", "here-web.db-wal", "here-web.db-shm", "here-web.db-journal",
    };
    char p[TEST_TMP_MAX + 32];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(p, sizeof(p), "%s/%s", g_dir, names[i]);
        unlink(p);
    }
    rmdir(g_dir);
}

static int sql_on(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    int rc = sqlite3_open(path, &h);
    if (rc == SQLITE_OK) rc = sqlite3_exec(h, sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) fprintf(stderr, "    sql: %s\n", sqlite3_errmsg(h));
    sqlite3_close(h);
    return rc == SQLITE_OK ? 0 : -1;
}

static long long q1(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    long long v = -1;
    if (sqlite3_open_v2(path, &h, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW)
            v = sqlite3_column_int64(st, 0);
        else
            fprintf(stderr, "    q1: %s\n", sqlite3_errmsg(h));
        sqlite3_finalize(st);
    }
    sqlite3_close(h);
    return v;
}

/* A sloth.db with sdb_seed()'s scenario (its cleartext credential among
 * it: the username alice-secret-user in cleartext_creds, in an alert's
 * key and in its detail) and, in the tables no export statement may
 * read, the other things that must never travel: EAPOL rows, a RADIUS
 * identity, an MQTT username, an RDP cookie. slothweb.db with a triage
 * decision whose note and author must stay here. */
static void up(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-fleet-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    snprintf(g_store, sizeof(g_store), "%s/slothweb.db", g_dir);
    WT_EQ(sdb_make(g_db, db_schema_version(), 0), 0);
    WT_EQ(sdb_seed(g_db), 0);
    char sql[2048];
    snprintf(sql, sizeof(sql),
        "INSERT INTO eapol_events (bssid,sta_mac,ts,msg_num,ssid,has_pmkid,"
        "handshake_complete,first_seen,last_seen) VALUES"
        " ('0e:ee:ee:ee:ee:01','02:ee:ee:ee:ee:02',%lld,2,'eapol-marker-ssid',1,1,%lld,%lld);"
        "INSERT INTO rogue_radius (bssid,identity_leaks,last_identity,first_seen,"
        "last_seen) VALUES ('0e:ee:ee:ee:ee:03',1,'radius-identity-marker',%lld,%lld);"
        "INSERT INTO mqtt_flows (src_ip,dst_ip,connect_count,last_username,first_seen,"
        "last_seen) VALUES ('10.0.4.1','10.0.4.2',1,'mqtt-user-marker',%lld,%lld);"
        "INSERT INTO rdp_flows (src_ip,dst_ip,connect_req_count,last_cookie,proto_mask,"
        "first_seen,last_seen) VALUES ('10.0.4.3','10.0.4.4',1,'mstshash=rdp-marker',1,"
        "%lld,%lld);"
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,technique,"
        "match_ip,match_port,count) VALUES ('pmkid:0e:ee:ee:ee:ee:01:deadbeefcafe',%lld,"
        "%lld,5,1,'PMKID exposed','pmkid=deadbeefcafe0123','T1557',NULL,NULL,1);",
        T - 50, T - 50, T - 50, T - 45, T - 44, T - 40, T - 30, T - 40, T - 30, T - 70,
        T - 60);
    WT_EQ(sdb_exec(g_db, sql), 0);
    web_slothdb_init(&SDB, g_db, NULL);
    char err[512];
    WT_EQ(web_store_open(&S, g_store, err, sizeof(err)), 0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO triage (subject,finding,type,addr,port,first_seen,state,ts,note,"
        "who,peer) VALUES ('x12:%lld',NULL,12,'10.0.1.5',21,%lld,4,%lld,"
        "'triage-note-marker','op-marker','127.0.0.1'),"
        " ('x0:%lld',NULL,0,'10.0.0.7',0,%lld,1,%lld,'','','127.0.0.1');",
        T - 100, T - 100, T - 90, T - 30 * DY, T - 30 * DY, T - 20 * DY);
    WT_EQ(sql_on(g_store, sql), 0);
    WT_EQ(web_frrs_init(&FR, &S, NULL, 1, err, sizeof(err)), 0);
}

static void down(void) {
    web_frrs_destroy(&FR);
    web_slothdb_destroy(&SDB);
    web_store_close(&S);
    rm_dir();
}

static char *export(long long since_q, const char *query, int *status) {
    web_fleet_src_t src = { &SDB, NULL, NULL, &FR };
    char q[64];
    if (!query) snprintf(q, sizeof(q), "since=%lld", since_q);
    char *body = NULL;
    size_t len = 0;
    WT_EQ(web_fleet_export_route(&src, query ? query : q, T, &body, &len, status), 0);
    if (!body) return NULL;
    char *t = realloc(body, len + 1);
    if (!t) { free(body); return NULL; }
    t[len] = '\0';
    return t;
}

/* The export over the seeded files: the device, its association and its
 * probe list, the AP, the alerts by type, title and fingerprint, the
 * verdict by descriptor and state; and nothing it must not carry. Every
 * line decodes, every member is listed, and the importer takes it.
 * The username's absence was seen red with web_sdb_alerts_between()'s
 * statement selecting alerts.detail in place of the title and
 * alerts.detail put on M4's allow-list (the reader's two guards changed
 * together: either alone still holds it out), "alice-detail" then in the
 * body; the note's with web_frrs_verdicts() reading note into addr. */
static void test_export_withholds_secrets(void) {
    up();
    int st = 0;
    char *b = export(0, NULL, &st);
    WT_EQ(st, 200);
    WT_ASSERT(b != NULL);
    if (!b) { down(); return; }
    WT_HAS(b, "{\"type\":\"fleet_export\",\"fleet_export_version\":1,\"generated\":");
    WT_HAS(b, ",\"sloth_db\":\"open\",\"lat\":null,");
    WT_HAS(b, "{\"type\":\"wifi\",\"mac\":\"da:a1:19:00:00:01\",\"vendor\":\"Apple\","
              "\"ssid\":\"HomeNet\",\"rssi\":-48,\"bssid\":\"aa:bb:cc:dd:ee:ff\","
              "\"is_ap\":false,");
    WT_HAS(b, "{\"type\":\"probe\",\"mac\":\"da:a1:19:00:00:01\",\"ssid\":\"HomeNet\",");
    WT_HAS(b, "{\"type\":\"probe\",\"mac\":\"da:a1:19:00:00:01\",\"ssid\":\"CafeFree\",");
    WT_HAS(b, "{\"type\":\"alert\",\"alert_type\":");
    WT_HAS(b, ",\"title\":\"FTP login in cleartext\",\"ip\":\"10.0.1.5\",\"sev\":2,\"count\":3,");
    WT_HAS(b, ",\"title\":\"PMKID exposed\",");
    WT_HAS(b, "{\"type\":\"verdict\",\"alert_type\":");
    WT_HAS(b, ",\"addr\":\"10.0.1.5\",\"port\":21,");
    WT_HAS(b, ",\"state\":\"known\",");
    WT_HAS(b, "\"complete\":true}\n");
    /* The things that must never travel. */
    static const char *const never[] = {
        "alice", "cred:", "user=", "eapol-marker", "02:ee:ee:ee:ee:02",
        "radius-identity", "mqtt-user", "mstshash", "rdp-marker", "deadbeef",
        "pmkid:", "triage-note-marker", "op-marker", "127.0.0.1",
    };
    for (size_t i = 0; i < sizeof(never) / sizeof(never[0]); i++) WT_LACKS(b, never[i]);
    /* Every line decodes and lists only its own members. */
    web_jrec_t *rec = malloc(sizeof(*rec));
    int lines = 0;
    for (char *p = b; rec && *p;) {
        char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        WT_EQ(web_jl_parse(p, n, rec), WEB_JL_OK);
        const char *const *m = web_fleet_members_of(web_jl_str(rec, "type"));
        WT_ASSERT(m != NULL);
        for (int i = 0; m && i < rec->n; i++) {
            int ok = !strcmp(rec->f[i].key, "type");
            for (int k = 1; m[k] && !ok; k++) ok = !strcmp(m[k], rec->f[i].key);
            WT_ASSERT(ok);
        }
        lines++;
        p = nl ? nl + 1 : p + n;
    }
    free(rec);
    WT_ASSERT(lines >= 15);
    /* The importer takes what the exporter writes. */
    web_fleet_t f;
    web_fleet_peer_cfg_t pc;
    char err[200];
    WT_EQ(web_fleet_parse_peer("self=http://100.64.0.1:8770", &pc, err, sizeof(err)), 0);
    web_fleet_init(&f, &pc, 1, 60, 0, &S);
    long long rows = 0, rts = 0;
    int rc = web_fleet_ingest(&f, 0, b, strlen(b), T, 0, &rows, &rts, err, sizeof(err));
    if (rc) fprintf(stderr, "    ingest: %s\n", err);
    WT_EQ(rc, 0);
    WT_EQ(rts, T);
    WT_ASSERT(rows >= 12);
    web_fleet_destroy(&f);
    free(b);
    down();
}

/* `since`: a row last seen before it is not sent; the parameter is
 * checked. Seen red with the export reading from 0 whatever since
 * says. */
static void test_export_since(void) {
    up();
    int st = 0;
    char *b = export(T - 2 * HR, NULL, &st);
    WT_EQ(st, 200);
    if (b) {
        WT_HAS(b, "\"mac\":\"da:a1:19:00:00:01\"");       /* seen 1 h ago */
        WT_HAS(b, "\"mac\":\"00:11:22:33:44:55\"");       /* 10 s ago */
        WT_LACKS(b, "\"mac\":\"da:a1:19:00:00:02\"");     /* 30 h ago */
        WT_LACKS(b, "\"mac\":\"f2:11:22:00:00:06\"");     /* 23 h ago */
        WT_LACKS(b, "\"mac\":\"da:a1:19:00:00:07\"");     /* 24 h ago */
        WT_LACKS(b, "\"state\":\"false\"");               /* decided 20 d ago */
        WT_HAS(b, "\"state\":\"known\"");
    }
    free(b);
    b = export(0, "since=12x", &st);
    WT_EQ(st, 400);
    if (b) WT_HAS(b, "bad_since");
    free(b);
    b = export(0, "since=1&limit=2", &st);
    WT_EQ(st, 400);
    if (b) WT_HAS(b, "unknown_parameter");
    free(b);
    b = export(0, "from=1", &st);
    WT_EQ(st, 400);
    free(b);
    b = export(0, "", &st);
    WT_EQ(st, 200);
    if (b) WT_HAS(b, "\"mac\":\"da:a1:19:00:00:02\"");
    free(b);
    /* Through the route table: JSON Lines, GET only. */
    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    m4.sdb = &SDB;
    m4.frrs = &FR;
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T;
    h.m4 = &m4;
    static char out[65536];
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "/api/fleet/export");
    snprintf(rq.query, sizeof(rq.query), "since=%lld", T - 60);
    snprintf(rq.host, sizeof(rq.host), "100.64.0.1:8770");
    rq.host_count = 1;
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 200);
    out[r.out_len] = '\0';
    WT_HAS(out, "Content-Type: application/x-ndjson\r\n");
    WT_ASSERT(r.body_owned != NULL && r.body_len > 0);
    free(r.body_owned);
    rq.is_head = 1;
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 405);
    down();
}

/* A row the importer would refuse is not sent: one such row refuses the
 * peer's whole answer, at every pull, while it is in the window. A device
 * whose stored signal is +60 dBm (outside the importer's -150..30) and
 * one whose first seen is after its last seen are left out, the wifi
 * kind is marked truncated, and the answer is still taken. Seen red with
 * row_end()'s self-check removed (the importer then refused the answer:
 * "line N: a wifi line with a value out of range"). */
static void test_export_sends_only_what_the_importer_takes(void) {
    up();
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,vendor,is_ap,signal_dbm,first_seen,last_seen) VALUES"
        " ('02:0b:ad:00:00:60','Odd',0,60,%lld,%lld),"
        " ('02:0b:ad:00:00:61','Odd',0,-50,%lld,%lld);",
        T - 100, T - 20, T - 5, T - 30);
    WT_EQ(sdb_exec(g_db, sql), 0);
    int st = 0;
    char *b = export(0, NULL, &st);
    WT_EQ(st, 200);
    if (b) {
        WT_LACKS(b, "02:0b:ad:00:00:6");
        WT_HAS(b, "\"mac\":\"da:a1:19:00:00:01\"");
        WT_HAS(b, "\"truncated_wifi\":true");
        WT_HAS(b, "\"truncated_ap\":false");
        web_fleet_t f;
        web_fleet_peer_cfg_t pc;
        char err[200];
        WT_EQ(web_fleet_parse_peer("self=http://100.64.0.1:8770", &pc, err, sizeof(err)), 0);
        web_fleet_init(&f, &pc, 1, 60, 0, &S);
        long long rows = 0, rts = 0;
        int rc = web_fleet_ingest(&f, 0, b, strlen(b), T, 0, &rows, &rts, err, sizeof(err));
        if (rc) fprintf(stderr, "    ingest: %s\n", err);
        WT_EQ(rc, 0);
        web_fleet_destroy(&f);
    }
    free(b);
    down();
}

/* ── the pull, from a loopback server ───────────────────────────────── */

typedef struct {
    int         lfd;
    const char *resp;
    size_t      len;
    char        req[512];
} srv_t;

static void *serve_once(void *arg) {
    srv_t *s = arg;
    int fd = accept(s->lfd, NULL, NULL);
    if (fd < 0) return NULL;
    size_t n = 0;
    while (n + 1 < sizeof(s->req)) {
        ssize_t k = recv(fd, s->req + n, sizeof(s->req) - 1 - n, 0);
        if (k <= 0) break;
        n += (size_t)k;
        s->req[n] = '\0';
        if (strstr(s->req, "\r\n\r\n")) break;
    }
    for (size_t o = 0; o < s->len;) {
        ssize_t k = send(fd, s->resp + o, s->len - o, MSG_NOSIGNAL);
        if (k <= 0) break;
        o += (size_t)k;
    }
    close(fd);
    return NULL;
}

static web_fleet_t F;

/* One pull of peer 0 against a server answering resp (headers added
 * here unless raw). The pull's return. */
static int pull_with(const char *resp, int raw, char *req, size_t reqsz) {
    srv_t s;
    memset(&s, 0, sizeof(s));
    s.lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    WT_EQ(bind(s.lfd, (struct sockaddr *)&sa, sizeof(sa)), 0);
    WT_EQ(listen(s.lfd, 1), 0);
    socklen_t sl = sizeof(sa);
    getsockname(s.lfd, (struct sockaddr *)&sa, &sl);
    F.peer[0].cfg.port = ntohs(sa.sin_port);
    char *full = NULL;
    if (raw) {
        s.resp = resp;
        s.len = strlen(resp);
    } else {
        size_t bl = strlen(resp);
        full = malloc(bl + 256);
        int hl = snprintf(full, 256, "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n"
                          "Content-Length: %zu\r\nConnection: close\r\n\r\n", bl);
        memcpy(full + hl, resp, bl + 1);
        s.resp = full;
        s.len = (size_t)hl + bl;
    }
    pthread_t th;
    pthread_create(&th, NULL, serve_once, &s);
    int rc = web_fleet_pull_one(&F, 0, T);
    pthread_join(th, NULL);
    close(s.lfd);
    free(full);
    if (req) snprintf(req, reqsz, "%s", s.req);
    return rc;
}

#define HDR(gen) "{\"type\":\"fleet_export\",\"fleet_export_version\":1,\"generated\":" #gen \
    ",\"since\":0,\"site_label\":\"beta-site\",\"slothweb_version\":\"1.8.6\"," \
    "\"sloth_version\":null,\"sloth_db\":\"open\",\"lat\":41.8781136,\"lon\":-87.6297982," \
    "\"alt_m\":181.0,\"pos_source\":\"fixed\",\"pos_ts\":" #gen ",\"pos_age_s\":0}\n"

static const char GOOD[] =
    HDR(1792627000)
    "{\"type\":\"gnss\",\"gps_state\":\"fixed\",\"sats_in_view\":12,\"sats_used\":9,"
    "\"cn0_mean\":38.5,\"time_offset_ms\":null,\"jam\":3,\"ts\":1792626990}\n"
    "{\"type\":\"wifi\",\"mac\":\"DA:A1:19:00:00:01\",\"vendor\":\"Apple\",\"ssid\":\"HomeNet\","
    "\"rssi\":-48,\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"is_ap\":false,\"first_seen\":1792600000,"
    "\"last_seen\":1792626000}\n"
    "{\"type\":\"ble\",\"addr\":\"c0:ff:ee:00:00:01\",\"addr_type\":\"r\",\"name\":\"tag\","
    "\"class\":\"tag\",\"rssi\":-70,\"first_seen\":1792620000,\"last_seen\":1792626500}\n"
    "{\"type\":\"ap\",\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"ssid\":\"HomeNet\",\"channel\":6,"
    "\"enc\":\"WPA2\",\"vendor\":null,\"rssi\":-40,\"first_seen\":1792500000,"
    "\"last_seen\":1792626900}\n"
    "{\"type\":\"probe\",\"mac\":\"da:a1:19:00:00:01\",\"ssid\":\"W9FJC-home\","
    "\"first_seen\":1792610000,\"last_seen\":1792626000}\n"
    "{\"type\":\"alert\",\"alert_type\":\"EVIL_TWIN\",\"ty\":18,\"fingerprint\":"
    "\"0123456789abcdef\",\"title\":\"Evil twin\",\"ip\":null,\"sev\":1,\"count\":4,"
    "\"first_seen\":1792620000,\"last_seen\":1792626000}\n"
    "{\"type\":\"verdict\",\"alert_type\":\"EVIL_TWIN\",\"addr\":\"aa:bb:cc:dd:ee:ff\","
    "\"port\":0,\"alert_first_seen\":1792620000,\"state\":\"known\",\"ts\":1792626100}\n"
    "{\"type\":\"wifi\",\"mac\":\"02:00:00:00:00:99\",\"vendor\":null,\"ssid\":null,"
    "\"rssi\":null,\"bssid\":null,\"is_ap\":false,\"first_seen\":1700000000,"
    "\"last_seen\":1700000000}\n"
    "{\"type\":\"fleet_end\",\"rows\":7,\"wifi\":2,\"ble\":1,\"ap\":1,\"probe\":1,\"alert\":1,"
    "\"verdict\":1,\"truncated_wifi\":false,\"truncated_ble\":false,\"truncated_ap\":false,"
    "\"truncated_probe\":false,\"truncated_alert\":false,\"truncated_verdict\":false,"
    "\"complete\":true}\n";

/* The second answer: the device again, heard earlier and later than the
 * first said, and nothing else. */
static const char GOOD2[] =
    HDR(1792627600)
    "{\"type\":\"wifi\",\"mac\":\"da:a1:19:00:00:01\",\"vendor\":\"Apple\",\"ssid\":\"CafeFree\","
    "\"rssi\":-60,\"bssid\":null,\"is_ap\":false,\"first_seen\":1792500000,"
    "\"last_seen\":1792627500}\n"
    "{\"type\":\"fleet_end\",\"rows\":1,\"wifi\":1,\"ble\":0,\"ap\":0,\"probe\":0,\"alert\":0,"
    "\"verdict\":0,\"truncated_wifi\":false,\"truncated_ble\":false,\"truncated_ap\":false,"
    "\"truncated_probe\":false,\"truncated_alert\":false,\"truncated_verdict\":false,"
    "\"complete\":true}\n";

static void pull_up(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-pull-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_store, sizeof(g_store), "%s/slothweb.db", g_dir);
    char err[512];
    WT_EQ(web_store_open(&S, g_store, err, sizeof(err)), 0);
    web_fleet_peer_cfg_t pc;
    WT_EQ(web_fleet_parse_peer("beta=http://127.0.0.1:1", &pc, err, sizeof(err)), 0);
    web_fleet_init(&F, &pc, 1, 60, 1, &S);
    F.connect_ms = 2000;
    F.read_ms = 5000;
    /* The pull thread's connection, without the thread: the tests step
     * the pull themselves. */
    WT_EQ(web_store_open_aux(&S, &F.wr, err, sizeof(err)), 0);
}

static void pull_down(void) {
    web_fleet_destroy(&F);
    web_store_close(&S);
    rm_dir();
}

static long long sightings(void) {
    return q1(g_store, "SELECT COUNT(*) FROM peer_sightings");
}

/* A good answer is stored whole: the site and its position, each kind
 * keyed canonically (the upper-case MAC lower-cased), a row older than
 * WEB_FLEET_KEEP_S by the peer's own clock dropped by the bound; the
 * first request asks since=0. The second asks from the peer's clock
 * less the overlap, and widens the device's first and last seen while
 * taking its newest label. Seen red with the upsert's first_seen CASE
 * replaced by excluded.first_seen (and with the age bound's DELETE
 * removed: 02:..:99 kept). */
static void test_pull_good_and_upsert(void) {
    pull_up();
    char req[512];
    int rc = pull_with(GOOD, 0, req, sizeof(req));
    if (rc) fprintf(stderr, "    pull: %s\n", F.peer[0].last_error);
    WT_EQ(rc, 0);
    WT_HAS(req, "GET /api/fleet/export?since=0&next=1 HTTP/1.1\r\n");
    WT_HAS(req, "Host: 127.0.0.1:");
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sites WHERE peer='beta' AND"
                      " label='beta-site' AND pos_source='fixed' AND lat>41.87 AND"
                      " lat<41.88 AND remote_ts=1792627000 AND rows_last=7 AND"
                      " last_error='' AND last_ok>0"), 1);
    WT_EQ(sightings(), 7);    /* 6 kinds and the receiver; 02:..:99 aged out */
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                      " key='da:a1:19:00:00:01' AND label='HomeNet' AND vendor='Apple'"
                      " AND rssi=-48 AND first_seen=1792600000 AND last_seen=1792626000"
                      " AND extra='{\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"is_ap\":false}'"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE"
                      " key='02:00:00:00:00:99'"), 0);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='probe' AND"
                      " key='da:a1:19:00:00:01|W9FJC-home'"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='verdict' AND"
                      " key='EVIL_TWIN|aa:bb:cc:dd:ee:ff|0|1792620000' AND label='known'"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='gnss' AND"
                      " key='receiver' AND label='fixed'"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='alert' AND"
                      " key='0123456789abcdef' AND label='Evil twin'"), 1);

    rc = pull_with(GOOD2, 0, req, sizeof(req));
    WT_EQ(rc, 0);
    WT_HAS(req, "GET /api/fleet/export?since=1792626880&next=1 HTTP/1.1\r\n");
    WT_EQ(sightings(), 7);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                      " key='da:a1:19:00:00:01' AND label='CafeFree' AND rssi=-60"
                      " AND first_seen=1792500000 AND last_seen=1792627500"), 1);
    /* An answer reporting less (an older last seen, a later first seen)
     * narrows nothing. */
    static const char OLD[] =
        HDR(1792627700)
        "{\"type\":\"wifi\",\"mac\":\"da:a1:19:00:00:01\",\"vendor\":\"Apple\",\"ssid\":\"x\","
        "\"rssi\":-61,\"bssid\":null,\"is_ap\":false,\"first_seen\":1792610000,"
        "\"last_seen\":1792611000}\n"
        "{\"type\":\"fleet_end\",\"rows\":1,\"wifi\":1,\"ble\":0,\"ap\":0,\"probe\":0,\"alert\":0,"
        "\"verdict\":0,\"truncated_wifi\":false,\"truncated_ble\":false,\"truncated_ap\":false,"
        "\"truncated_probe\":false,\"truncated_alert\":false,\"truncated_verdict\":false,"
        "\"complete\":true}\n";
    WT_EQ(pull_with(OLD, 0, NULL, 0), 0);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                      " key='da:a1:19:00:00:01' AND first_seen=1792500000 AND"
                      " last_seen=1792627500"), 1);
    /* /api/health and /api/fleet/peers. */
    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    m4.fleet = &F;
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T + 30;
    h.m4 = &m4;
    static char out[65536];
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "/api/health");
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_HAS(out, ",\"fleet\":{\"export\":true,\"export_version\":1,\"interval_s\":60,"
                "\"outside_tailnet\":true,\"peers\":[{\"name\":\"beta\",\"url\":"
                "\"http://127.0.0.1:1\",\"last_ok_age_s\":30,\"last_attempt_age_s\":30,"
                "\"last_error\":null,\"rows\":1,\"pulls\":3,\"failures\":0}]}");
    snprintf(rq.path, sizeof(rq.path), "/api/fleet/peers");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_HAS(out, "{\"export\":true,\"interval_s\":60,\"store\":true,\"peers\":[{\"name\":"
                "\"beta\",\"configured\":true,\"url\":\"http://127.0.0.1:1\",\"label\":"
                "\"beta-site\",");
    WT_HAS(out, ",\"lat\":41.8781136,\"lon\":-87.6297982,\"alt_m\":181.0,\"pos_source\":"
                "\"fixed\",");
    WT_HAS(out, ",\"counts\":{\"alert\":1,\"ap\":1,\"ble\":1,\"gnss\":1,\"probe\":1,"
                "\"verdict\":1,\"wifi\":1}}");
    snprintf(rq.query, sizeof(rq.query), "x=1");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 400);
    pull_down();
}

/* Each refused answer leaves every sighting and the last good pull as
 * they were, and says why. Seen red with the response-size checks in
 * http_get() removed (the oversize answer stored), with the ingest's
 * "no end line" refusal removed (that answer stored) and with
 * members_ok() returning 1 (the username line taken). */
static void test_pull_refusals(void) {
    pull_up();
    WT_EQ(pull_with(GOOD, 0, NULL, 0), 0);
    long long before = sightings();
    WT_EQ(before, 7);
    static const char FP[] = "SELECT COUNT(*) FROM peer_sites WHERE remote_ts=1792627000"
                             " AND rows_last=7 AND last_ok=" "1792627200";
    WT_EQ(q1(g_store, FP), 1);
    char line[512];
    struct { const char *what, *resp; int raw; const char *why; } cases[] = {
        { "malformed", HDR(1792627900) "{\"type\":\"wifi\",\"mac\":\n", 0, "line 2" },
        { "username member", HDR(1792627900)
          "{\"type\":\"wifi\",\"mac\":\"02:00:00:00:00:01\",\"username\":\"u-marker\","
          "\"first_seen\":1,\"last_seen\":2}\n"
          "{\"type\":\"fleet_end\",\"rows\":1,\"wifi\":1,\"ble\":0,\"ap\":0,\"probe\":0,"
          "\"alert\":0,\"verdict\":0,\"complete\":true}\n", 0, "may not carry" },
        { "no end line", HDR(1792627900)
          "{\"type\":\"wifi\",\"mac\":\"02:00:00:00:00:01\",\"first_seen\":1,"
          "\"last_seen\":2}\n", 0, "no end line" },
        { "count", HDR(1792627900)
          "{\"type\":\"wifi\",\"mac\":\"02:00:00:00:00:01\",\"first_seen\":1,"
          "\"last_seen\":2}\n"
          "{\"type\":\"fleet_end\",\"rows\":1,\"wifi\":2,\"ble\":0,\"ap\":0,\"probe\":0,"
          "\"alert\":0,\"verdict\":0,\"complete\":true}\n", 0, "wifi count" },
        { "version", "{\"type\":\"fleet_export\",\"fleet_export_version\":2,"
          "\"generated\":1792627900}\n{\"type\":\"fleet_end\",\"rows\":0,\"wifi\":0,"
          "\"ble\":0,\"ap\":0,\"probe\":0,\"alert\":0,\"verdict\":0,\"complete\":true}\n",
          0, "no fleet_export header" },
        { "bad mac", HDR(1792627900)
          "{\"type\":\"wifi\",\"mac\":\"not-a-mac\",\"first_seen\":1,\"last_seen\":2}\n", 0,
          "out of range" },
        { "status", "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n", 1,
          "HTTP status 503" },
        { "cut short", "HTTP/1.1 200 OK\r\nContent-Length: 9999\r\n\r\n"
          HDR(1792627900), 1, "cut short" },
        { "chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
          "1f4\r\n" HDR(1792627900) "\r\n0\r\n\r\n", 1, "Transfer-Encoding" },
        { "two lengths", "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n"
          "Content-Length: 10\r\n\r\n0123456789", 1, "two Content-Length" },
        { "length not a number", "HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n", 1,
          "not a number" },
        { "not http", "SSH-2.0-OpenSSH_9.6\r\n", 1, "not an HTTP response" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int rc = pull_with(cases[i].resp, cases[i].raw, NULL, 0);
        if (rc == 0) fprintf(stderr, "    taken: %s\n", cases[i].what);
        WT_EQ(rc, -1);
        snprintf(line, sizeof(line), "%s", F.peer[0].last_error);
        if (!strstr(line, cases[i].why))
            fprintf(stderr, "    %s: \"%s\"\n", cases[i].what, line);
        WT_HAS(line, cases[i].why);
        WT_EQ(sightings(), before);
        WT_EQ(q1(g_store, FP), 1);
        WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE"
                          " key LIKE '02:00:00:00:00:01%'"), 0);
    }
    /* The refusal is kept beside the last good pull. */
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sites WHERE last_error LIKE"
                      " '%not an HTTP response%'"), 1);
    /* Oversize: past resp_max, refused, never cut to fit. */
    /* A well-formed answer of 60 probe lines, some 7 KB: only its size
     * is wrong. */
    F.resp_max = 1024;
    char *huge = malloc(16384);
    size_t o = (size_t)snprintf(huge, 16384, "%s", HDR(1792627900));
    for (int i = 0; i < 60; i++)
        o += (size_t)snprintf(huge + o, 16384 - o, "{\"type\":\"probe\",\"mac\":"
                              "\"02:00:00:00:00:01\",\"ssid\":\"net-%02d\",\"first_seen\":1792620000,"
                              "\"last_seen\":1792626000}\n", i);
    snprintf(huge + o, 16384 - o, "{\"type\":\"fleet_end\",\"rows\":60,\"wifi\":0,"
             "\"ble\":0,\"ap\":0,\"probe\":60,\"alert\":0,\"verdict\":0,"
             "\"complete\":true}\n");
    WT_ASSERT(strlen(huge) > 4096);
    WT_EQ(pull_with(huge, 0, NULL, 0), -1);
    WT_HAS(F.peer[0].last_error, "over 1024 bytes");
    WT_EQ(sightings(), before);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE"
                      " key LIKE '02:00:00:00:00:01%'"), 0);
    free(huge);
    F.resp_max = WEB_FLEET_RESP_MAX;
    /* And a good one after them all is stored. */
    WT_EQ(pull_with(GOOD2, 0, NULL, 0), 0);
    WT_EQ(F.peer[0].last_error[0], '\0');
    WT_EQ(F.peer[0].failures, 13);
    pull_down();
}

/* A peer that answers a byte at a time and never finishes. */
typedef struct {
    int lfd;
} trickle_t;

static void *serve_trickle(void *arg) {
    trickle_t *t = arg;
    int fd = accept(t->lfd, NULL, NULL);
    if (fd < 0) return NULL;
    char rq[512];
    (void)recv(fd, rq, sizeof(rq), 0);
    static const char H[] = "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n";
    if (send(fd, H, sizeof(H) - 1, MSG_NOSIGNAL) > 0) {
        /* A byte every 50 ms for up to 20 s, until the client hangs up. */
        for (int i = 0; i < 400; i++) {
            if (send(fd, "{", 1, MSG_NOSIGNAL) != 1) break;
            usleep(50000);
        }
    }
    close(fd);
    return NULL;
}

static long long ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* The read deadline is the whole answer's, not each read's: a peer that
 * keeps a trickle going is cut off at read_ms, not held for as long as
 * it likes. Seen red with http_get() renewing the deadline after each
 * read (the pull then ran the trickle's whole 20 s and failed for
 * another reason). */
static void test_pull_trickle_is_cut_off(void) {
    pull_up();
    trickle_t t;
    t.lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    WT_EQ(bind(t.lfd, (struct sockaddr *)&sa, sizeof(sa)), 0);
    WT_EQ(listen(t.lfd, 1), 0);
    socklen_t sl = sizeof(sa);
    getsockname(t.lfd, (struct sockaddr *)&sa, &sl);
    F.peer[0].cfg.port = ntohs(sa.sin_port);
    F.read_ms = 600;
    pthread_t th;
    pthread_create(&th, NULL, serve_trickle, &t);
    long long t0 = ms_now();
    WT_EQ(web_fleet_pull_one(&F, 0, T), -1);
    long long ms = ms_now() - t0;
    pthread_join(th, NULL);
    close(t.lfd);
    if (!strstr(F.peer[0].last_error, "timed out"))
        fprintf(stderr, "    trickle: \"%s\" after %lld ms\n", F.peer[0].last_error, ms);
    WT_HAS(F.peer[0].last_error, "read: timed out");
    WT_ASSERT(ms < 600 + 2000LL * web_sdb_test_budget_scale);
    WT_EQ(sightings(), 0);
    pull_down();
}

/* No peer reachable: a refused connection is an error in words, and the
 * thread's start and stop are clean with a peer configured (the pull
 * runs at once and fails, the stop is prompt). */
static void test_pull_unreachable_and_thread(void) {
    pull_up();
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(s, (struct sockaddr *)&sa, sizeof(sa));
    socklen_t sl = sizeof(sa);
    getsockname(s, (struct sockaddr *)&sa, &sl);
    close(s);                         /* nothing listens there now */
    F.peer[0].cfg.port = ntohs(sa.sin_port);
    WT_EQ(web_fleet_pull_one(&F, 0, T), -1);
    WT_HAS(F.peer[0].last_error, "connect: ");
    WT_EQ(sightings(), 0);
    web_fleet_destroy(&F);
    web_fleet_peer_cfg_t pc = F.peer[0].cfg;
    web_fleet_init(&F, &pc, 1, 3600, 1, &S);
    char err[256];
    WT_EQ(web_fleet_start(&F, err, sizeof(err)), 0);
    WT_EQ(F.started, 1);
    unsigned long pulls = 0;
    for (int i = 0; i < 500 && !pulls; i++) {
        pthread_mutex_lock(&F.mu);
        pulls = F.peer[0].pulls;
        pthread_mutex_unlock(&F.mu);
        if (!pulls) usleep(10000);
    }
    WT_ASSERT(pulls >= 1);
    web_fleet_stop(&F);
    WT_EQ(F.started, 0);
    pull_down();
}


/* ── F2: the backfill, against the real export ─────────────────────── */

/* A peer: a loopback server answering every request with
 * web_fleet_export_route() over the peer's own files (SDB, FR), until
 * stopped; each request's target kept. */
typedef struct {
    int       lfd, stop, n;
    int       f1;                     /* answer as an F1 export: a 400 for any '&' */
    pthread_mutex_t mu;               /* guards stop */
    char      req[24][256];
    web_fleet_src_t src;
} peer_srv_t;

static int srv_stopped(peer_srv_t *s) {
    pthread_mutex_lock(&s->mu);
    int v = s->stop;
    pthread_mutex_unlock(&s->mu);
    return v;
}

static void *serve_export(void *arg) {
    peer_srv_t *s = arg;
    for (;;) {
        struct pollfd pf = { s->lfd, POLLIN, 0 };
        int r = poll(&pf, 1, 50);
        if (srv_stopped(s)) break;
        if (r <= 0) continue;
        int fd = accept(s->lfd, NULL, NULL);
        if (fd < 0) continue;
        char rq[1024];
        size_t n = 0;
        while (n + 1 < sizeof(rq)) {
            ssize_t k = recv(fd, rq + n, sizeof(rq) - 1 - n, 0);
            if (k <= 0) break;
            n += (size_t)k;
            rq[n] = '\0';
            if (strstr(rq, "\r\n\r\n")) break;
        }
        rq[n] = '\0';
        const char *q = strstr(rq, "/api/fleet/export?");
        const char *sp = q ? strchr(q, ' ') : NULL;
        char query[256] = "";
        if (q && sp && (size_t)(sp - q - 18) < sizeof(query)) {
            memcpy(query, q + 18, (size_t)(sp - q - 18));
            query[sp - q - 18] = '\0';
        }
        if (s->n < 24) snprintf(s->req[s->n++], sizeof(s->req[0]), "%s", query);
        char *body = NULL;
        size_t bl = 0;
        int st = 0;
        if (s->f1 && strchr(query, '&')) {
            /* F1's parse_since(): since= alone, else unknown_parameter. */
            body = malloc(64);
            if (body) bl = (size_t)snprintf(body, 64, "{\"error\":\"unknown_parameter\"}");
            st = 400;
        } else {
            web_fleet_export_route(&s->src, query, T, &body, &bl, &st);
        }
        char hdr[160];
        int hl = snprintf(hdr, sizeof(hdr), "HTTP/1.1 %d X\r\nContent-Length: %zu\r\n"
                          "Connection: close\r\n\r\n", st, bl);
        send(fd, hdr, (size_t)hl, MSG_NOSIGNAL);
        for (size_t o = 0; body && o < bl;) {
            ssize_t k = send(fd, body + o, bl - o, MSG_NOSIGNAL);
            if (k <= 0) break;
            o += (size_t)k;
        }
        free(body);
        close(fd);
    }
    return NULL;
}

static web_store_t S2;
static char g_here_db[TEST_TMP_MAX + 32], g_here_web[TEST_TMP_MAX + 32];

/* The peer is up()'s files; this site's store is here-web.db, F pulling
 * the peer at a loopback port. */
static void here_up(peer_srv_t *srv, pthread_t *th) {
    up();
    snprintf(g_here_web, sizeof(g_here_web), "%s/here-web.db", g_dir);
    snprintf(g_here_db, sizeof(g_here_db), "%s/here.db", g_dir);
    char err[512];
    WT_EQ(web_store_open(&S2, g_here_web, err, sizeof(err)), 0);
    web_fleet_peer_cfg_t pc;
    WT_EQ(web_fleet_parse_peer("beta=http://127.0.0.1:1", &pc, err, sizeof(err)), 0);
    web_fleet_init(&F, &pc, 1, 60, 1, &S2);
    F.connect_ms = 2000;
    F.read_ms = 10000;
    WT_EQ(web_store_open_aux(&S2, &F.wr, err, sizeof(err)), 0);
    memset(srv, 0, sizeof(*srv));
    pthread_mutex_init(&srv->mu, NULL);
    srv->src.sdb = &SDB;
    srv->src.frrs = &FR;
    srv->lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    WT_EQ(bind(srv->lfd, (struct sockaddr *)&sa, sizeof(sa)), 0);
    WT_EQ(listen(srv->lfd, 8), 0);
    socklen_t sl = sizeof(sa);
    getsockname(srv->lfd, (struct sockaddr *)&sa, &sl);
    F.peer[0].cfg.port = ntohs(sa.sin_port);
    pthread_create(th, NULL, serve_export, srv);
}

static void here_down(peer_srv_t *srv, pthread_t th) {
    pthread_mutex_lock(&srv->mu);
    srv->stop = 1;
    pthread_mutex_unlock(&srv->mu);
    pthread_join(th, NULL);
    pthread_mutex_destroy(&srv->mu);
    close(srv->lfd);
    web_fleet_destroy(&F);
    web_store_close(&S2);
    down();
}

static long long here_q(const char *sql) { return q1(g_here_web, sql); }

/* More of each pageable kind than one answer carries, most of them in
 * ties on last_seen across the cut, all of them older than the next
 * pull's window: the first pull takes the newest of each and one page
 * after it (pages_per_pull 1), a restart reads the backfill back from
 * meta, and the next pull's page finishes it. Every row arrives once,
 * the incremental pull never asks for them again, and the meta row is
 * gone when the kind is whole. Seen red with the page request's
 * &after= dropped (every page answered the top again: wifi stayed at
 * 2,000 of 4,509, ap, alert and verdict at 1,000, every backfill still
 * running), with the device reader's tie term (d.last_seen = ?5 AND
 * d.mac > ?6) removed (the rows of the cut's tie group after the cursor
 * never came: 4,004 of 4,509), and with bf_meta_write() not called (the
 * restart forgot the backfill: 4,000). */
static void test_backfill_after_a_cut(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    char sql[4096];
    snprintf(sql, sizeof(sql),
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<4499)"
        " INSERT INTO devices (mac,vendor,is_ap,signal_dbm,first_seen,last_seen)"
        " SELECT printf('02:aa:00:00:%%02x:%%02x', i/256, i%%256),'Bulk',0,-60,%lld,"
        " %lld-(i%%4) FROM n;"
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<1299)"
        " INSERT INTO beacon_aps (bssid,ssid,channel,signal_dbm,first_seen,last_seen)"
        " SELECT printf('0a:bb:00:00:%%02x:%%02x', i/256, i%%256),'bulk-net',6,-70,%lld,"
        " %lld-(i%%3) FROM n;"
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<1099)"
        " INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,technique,count)"
        " SELECT 'bulk:'||i,%lld,%lld-(i%%5),3,1,'bulk alert '||i,'T1557',1 FROM n;",
        T - 5000, T - 1000, T - 5000, T - 2000, T - 4000, T - 3000);
    WT_EQ(sdb_exec(g_db, sql), 0);
    snprintf(sql, sizeof(sql),
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<1099)"
        " INSERT INTO triage (subject,finding,type,addr,port,first_seen,state,ts,note,who,peer)"
        " SELECT 'b'||i,NULL,12,printf('10.9.%%d.%%d', i/256, i%%256),0,%lld,4,%lld-(i%%5),"
        "'','','127.0.0.1' FROM n;", T - 4000, T - 3000);
    WT_EQ(sql_on(g_store, sql), 0);
    long long want_wifi = q1(g_db, "SELECT COUNT(*) FROM devices");
    long long want_ap = q1(g_db, "SELECT COUNT(*) FROM beacon_aps");
    long long want_alert = q1(g_db, "SELECT COUNT(DISTINCT type||'|'||title) FROM alerts");
    long long want_verdict = q1(g_store, "SELECT COUNT(DISTINCT subject) FROM triage");
    WT_ASSERT(want_wifi > 2 * WEB_FLEET_CAP_WIFI && want_ap > WEB_FLEET_CAP_AP &&
              want_alert > WEB_FLEET_CAP_ALERT && want_verdict > WEB_FLEET_CAP_VERDICT);

    F.pages_per_pull = 1;
    int rc = web_fleet_pull_one(&F, 0, T);
    if (rc) fprintf(stderr, "    pull 1: %s\n", F.peer[0].last_error);
    WT_EQ(rc, 0);
    WT_EQ(F.peer[0].page_failures, 0);
    if (F.peer[0].last_error[0]) fprintf(stderr, "    pull 1: %s\n", F.peer[0].last_error);
    /* The whole export, then one page of each cut kind from its floor. */
    WT_ASSERT(srv.n == 5);
    WT_ASSERT(!strcmp(srv.req[0], "since=0&next=1"));
    WT_ASSERT(!strncmp(srv.req[1], "since=0&kind=wifi&after=", 24));
    WT_ASSERT(!strncmp(srv.req[2], "since=0&kind=ap&after=", 22));
    WT_ASSERT(!strncmp(srv.req[3], "since=0&kind=alert&after=", 25));
    WT_ASSERT(!strncmp(srv.req[4], "since=0&kind=verdict&after=", 27));
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi'"), 2 * WEB_FLEET_CAP_WIFI);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='ap'"), want_ap);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='alert'"), want_alert);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='verdict'"), want_verdict);
    /* Only wifi is still running, and its state is in meta. */
    WT_EQ(F.peer[0].bf[WEB_FK_WIFI].active, 1);
    WT_EQ(F.peer[0].bf[WEB_FK_WIFI].floor, 0);
    WT_EQ(F.peer[0].bf[WEB_FK_AP].active + F.peer[0].bf[WEB_FK_ALERT].active +
          F.peer[0].bf[WEB_FK_VERDICT].active, 0);
    WT_EQ(here_q("SELECT COUNT(*) FROM meta WHERE name LIKE 'fleet.backfill.%'"), 1);
    WT_EQ(here_q("SELECT COUNT(*) FROM meta WHERE name='fleet.backfill.beta.wifi'"
                 " AND value LIKE '0 %~02:aa:00:00:%'"), 1);
    /* The rows of the overview's backfill state. */
    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    m4.fleet = &F;
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T;
    h.m4 = &m4;
    static char out[65536];
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "/api/fleet/overview");
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_HAS(out, ",\"backfill\":{\"wifi\":{\"floor\":0,\"cursor\":\"");
    WT_HAS(out, ",\"pages\":4,\"page_failures\":0,");

    /* A restart: the pull state from peer_sites, the backfill from meta. */
    web_fleet_peer_cfg_t pc = F.peer[0].cfg;
    web_fleet_destroy(&F);
    web_fleet_init(&F, &pc, 1, 60, 1, &S2);
    F.connect_ms = 2000;
    F.read_ms = 10000;
    F.pages_per_pull = 1;
    char err[256];
    WT_EQ(web_store_open_aux(&S2, &F.wr, err, sizeof(err)), 0);
    web_fleet_load(&F);
    WT_EQ(F.peer[0].remote_ts, T);
    WT_EQ(F.peer[0].bf[WEB_FK_WIFI].active, 1);
    rc = web_fleet_pull_one(&F, 0, T + 5);
    WT_EQ(rc, 0);
    WT_ASSERT(srv.n == 7);
    /* The incremental pull asks only for what is new; the page goes on
     * from the cursor. */
    char want[64];
    snprintf(want, sizeof(want), "since=%lld&next=1", T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[5], want));
    WT_ASSERT(!strncmp(srv.req[6], "since=0&kind=wifi&after=", 24));
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi'"), want_wifi);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                 " key LIKE '02:aa:%'"), 4500);
    WT_EQ(F.peer[0].bf[WEB_FK_WIFI].active, 0);
    WT_EQ(here_q("SELECT COUNT(*) FROM meta WHERE name LIKE 'fleet.backfill.%'"), 0);
    /* A third pull: nothing cut, so no page. */
    WT_EQ(web_fleet_pull_one(&F, 0, T + 65), 0);
    WT_ASSERT(srv.n == 8);
    here_down(&srv, th);
}

/* An alert key's incidents by the thousand fill the reader's
 * WEB_SDB_ALERT_SCAN window long before the cap, as they do on W9FJC
 * (364,191 incidents, the newest 20,000 of them 955 keys of 17,988):
 * three hot keys with 7,000 incidents each, newer than 1,500 keys with
 * one. The whole export sends the three uncut-looking keys, says the
 * kind was cut at the scan's oldest row, and the pages from there bring
 * every other key. Seen red with the scan-cap check removed from the
 * export (6 of 1,506 keys arrived, no page asked for) and with
 * web_sdb_alerts_upto()'s ceiling not applied (the page read the same
 * newest 20,000 rows, found nothing past its cursor and ended the
 * backfill: 6 of 1,506, no cold key). */
static void test_backfill_alerts_past_the_scan(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    char sql[4096];
    snprintf(sql, sizeof(sql),
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<2)"
        " INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,technique,count)"
        " SELECT 'hot:'||i,%lld,%lld,3,1,'hot alert '||i,'T1557',7000 FROM n;"
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<20999)"
        " INSERT INTO alert_incidents (key,incident_id,type,first_seen,last_seen,sev,"
        "peak_sev,count,observations) SELECT 'hot:'||(i%%3),printf('%%016x',i),3,"
        "%lld-(i/3)-10,%lld-(i/3),1,1,1,1 FROM n;"
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<1499)"
        " INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,technique,count)"
        " SELECT 'cold:'||i,%lld-i-10,%lld-i,3,1,'cold alert '||i,'T1557',1 FROM n;"
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<1499)"
        " INSERT INTO alert_incidents (key,incident_id,type,first_seen,last_seen,sev,"
        "peak_sev,count,observations) SELECT 'cold:'||i,'0000000000000001',3,%lld-i-10,"
        "%lld-i,1,1,1,1 FROM n;",
        T - 8100, T - 1000, T - 1000, T - 1000, T - 9000, T - 9000, T - 9000, T - 9000);
    WT_EQ(sdb_exec(g_db, sql), 0);
    long long want = q1(g_db, "SELECT COUNT(DISTINCT type||'|'||title) FROM alerts");
    WT_ASSERT(want > 1500);
    F.pages_per_pull = 4;
    WT_EQ(web_fleet_pull_one(&F, 0, T), 0);
    /* The first answer was cut by the scan, not the cap: fewer keys than
     * the cap, and a backfill. */
    WT_ASSERT(srv.n >= 2);
    WT_ASSERT(!strncmp(srv.req[1], "since=0&kind=alert&after=", 25));
    for (int i = 0; i < 6 && F.peer[0].bf[WEB_FK_ALERT].active; i++)
        WT_EQ(web_fleet_pull_one(&F, 0, T + 60 * (i + 1)), 0);
    WT_EQ(F.peer[0].bf[WEB_FK_ALERT].active, 0);
    WT_EQ(F.peer[0].page_failures, 0);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='alert'"), want);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='alert' AND"
                 " label LIKE 'cold alert %'"), 1500);
    /* A hot key given again from a page keeps its newest last_seen. */
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='alert' AND"
                 " label LIKE 'hot alert %' AND last_seen = (SELECT MAX(last_seen) FROM"
                 " peer_sightings WHERE kind='alert' AND label LIKE 'hot alert %')"), 3);
    here_down(&srv, th);
}

/* A fleet upgraded a host at a time: this F2 puller against an F1 peer,
 * whose export refuses next=1 as an unknown parameter. The pull asks
 * again without it and is stored; nothing is paged from that peer; the
 * next pull within WEB_FLEET_NONEXT_S asks plainly at once; the overview
 * says so. Seen red with the retry removed (the pull failed with HTTP
 * status 400 and no row was stored). */
static void test_pull_from_an_f1_peer(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    srv.f1 = 1;
    int rc = web_fleet_pull_one(&F, 0, T);
    if (rc) fprintf(stderr, "    pull: %s\n", F.peer[0].last_error);
    WT_EQ(rc, 0);
    WT_ASSERT(srv.n == 2);
    WT_ASSERT(!strcmp(srv.req[0], "since=0&next=1"));
    WT_ASSERT(!strcmp(srv.req[1], "since=0"));
    WT_ASSERT(here_q("SELECT COUNT(*) FROM peer_sightings WHERE peer='beta'") > 0);
    WT_EQ(F.peer[0].failures, 0);
    WT_EQ(F.peer[0].last_error[0], '\0');
    WT_ASSERT(F.peer[0].no_next_until > T);
    /* Within the hour: plain at once, one request. */
    WT_EQ(web_fleet_pull_one(&F, 0, T + 60), 0);
    WT_ASSERT(srv.n == 3);
    char want[64];
    snprintf(want, sizeof(want), "since=%lld", T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[2], want));
    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    m4.fleet = &F;
    web_fleet_src_t src = { NULL, NULL, NULL, NULL };
    static char body[65536];
    size_t len = 0;
    int st = 0;
    WT_EQ(web_fleet_overview_route(&F, &src, "", T + 60, body, sizeof(body) - 1, &len, &st), 0);
    body[len] = '\0';
    WT_EQ(st, 200);
    WT_HAS(body, ",\"pages_refused\":true,");
    /* After it: asked with next=1 again (the peer may have been
     * upgraded meanwhile). */
    srv.f1 = 0;
    WT_EQ(web_fleet_pull_one(&F, 0, T + 60 + WEB_FLEET_NONEXT_S), 0);
    WT_ASSERT(srv.n == 4);
    WT_ASSERT(strstr(srv.req[3], "&next=1") != NULL);
    here_down(&srv, th);
}

/* The export's paging, request by request: the parameters; an F1 pull
 * (no next=1) answered without a member an F1 importer would refuse; a
 * page of wifi after a cursor holding only that kind. Seen red with the
 * next_<kind> members written whatever the request (next_ in the plain
 * answer) and with the device reader's keyset made always true (the
 * cursor's own row and a newer one in the page). */
static void test_export_pages(void) {
    up();
    int st = 0;
    char *b = export(0, "since=0", &st);
    WT_EQ(st, 200);
    if (b) WT_LACKS(b, "next_");
    free(b);
    b = export(0, "since=0&next=1", &st);
    WT_EQ(st, 200);
    if (b) WT_HAS(b, ",\"next_wifi\":null,\"next_ap\":null,\"next_alert\":null,"
                     "\"next_verdict\":null,\"complete\":true}");
    free(b);
    /* A page: only its kind (and a client's probes), from the cursor. */
    b = export(0, "since=0&kind=wifi&after=1792623600~da:a1:19:00:00:01", &st);
    WT_EQ(st, 200);
    if (b) {
        WT_LACKS(b, "\"mac\":\"da:a1:19:00:00:01\"");   /* the cursor's own row */
        WT_LACKS(b, "\"mac\":\"00:11:22:33:44:55\"");   /* newer than it */
        WT_HAS(b, "\"mac\":\"da:a1:19:00:00:02\"");     /* older */
        WT_LACKS(b, "{\"type\":\"alert\"");
        WT_LACKS(b, "{\"type\":\"verdict\"");
        WT_LACKS(b, "{\"type\":\"gnss\"");
        WT_HAS(b, "\"next_wifi\":null");
    }
    free(b);
    static const struct { const char *q, *why; } bad[] = {
        { "since=0&kind=probe", "bad_kind" }, { "since=0&kind=ble", "bad_kind" },
        { "since=0&after=1~x", "after_needs_kind" }, { "kind=wifi&after=x~1", "bad_after" },
        { "kind=wifi&after=1~a-b", "bad_after" }, { "kind=wifi&after=1", "bad_after" },
        { "since=0&next=2", "bad_next" }, { "since=0&since=1", "unknown_parameter" },
        { "since=0&limit=1", "unknown_parameter" }, { "since", "unknown_parameter" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        b = export(0, bad[i].q, &st);
        if (st != 400) fprintf(stderr, "    taken: %s\n", bad[i].q);
        WT_EQ(st, 400);
        if (b) WT_HAS(b, bad[i].why);
        free(b);
    }
    WT_EQ(web_fleet_cursor_ok("1792623600~da:a1:19:00:00:01"), 1);
    WT_EQ(web_fleet_cursor_ok("4102444800~"), 1);
    WT_EQ(web_fleet_cursor_ok("~x"), 0);
    WT_EQ(web_fleet_cursor_ok("1234567890123~x"), 0);
    WT_EQ(web_fleet_cursor_ok("1~0123456789012345678901234"), 0);
    down();
}

/* The overview and the shared list over a pulled peer and this site's
 * own sloth.db (here.db): the keys both hold, each site's times and
 * signal, this site's verdict; nothing only the peer holds. Seen red
 * with the shared walk taking a key the local read did not find (the
 * peer's da:a1:19:00:00:02 and 00:11:22:33:44:55 listed, the HomeNet
 * probe too) and with the overview's skew written as last_ok -
 * remote_ts. A key only this site holds (02:10:ca:10:ca:01, OnlyHere)
 * cannot be listed by construction (the walk starts from the peer's
 * rows), so its absence is a statement of that, not a guard seen red.
 * The verdicts: the peer's "incident" at a device this site has not
 * triaged, never the peer's "noise" where this site said "known" (seen
 * red with this site's triage pass skipped: "noise" from beta shown). */
static void test_overview_and_shared(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    char sql[2048];
    /* The peer's verdicts at two of the devices: one this site has
     * triaged too (its own wins), one it has not (the peer's shown). */
    snprintf(sql, sizeof(sql),
        "INSERT INTO triage (subject,finding,type,addr,port,first_seen,state,ts,note,who,"
        "peer) VALUES ('p3a',NULL,3,'da:a1:19:00:00:01',0,%lld,2,%lld,'','',''),"
        " ('p3b',NULL,3,'da:a1:19:00:00:04',0,%lld,3,%lld,'','','');",
        T - 600, T - 590, T - 600, T - 580);
    WT_EQ(sql_on(g_store, sql), 0);
    WT_EQ(web_fleet_pull_one(&F, 0, T + 5), 0);
    WT_EQ(sdb_make(g_here_db, db_schema_version(), 0), 0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,vendor,is_ap,signal_dbm,first_seen,last_seen) VALUES"
        " ('da:a1:19:00:00:01','Apple',0,-41,%lld,%lld),"
        " ('da:a1:19:00:00:04','Samsung',0,-77,%lld,%lld),"
        " ('02:10:ca:10:ca:01','Here',0,-50,%lld,%lld);"
        "INSERT INTO pnl_clients (mac,mac_random,probe_count,first_seen,last_seen)"
        " VALUES ('da:a1:19:00:00:01',1,2,%lld,%lld);"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) VALUES"
        " ('da:a1:19:00:00:01','CafeFree',%lld,%lld),"
        " ('da:a1:19:00:00:01','OnlyHere',%lld,%lld);",
        T - 900, T - 30, T - 90000, T - 80000, T - 900, T - 20,
        T - 900, T - 30, T - 800, T - 40, T - 800, T - 40);
    WT_EQ(sdb_exec(g_here_db, sql), 0);
    web_slothdb_t here;
    web_slothdb_init(&here, g_here_db, NULL);
    web_frrs_t fr2;
    char err[256];
    WT_EQ(web_frrs_init(&fr2, &S2, NULL, 1, err, sizeof(err)), 0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO triage (subject,finding,type,addr,port,first_seen,state,ts,note,who,"
        "peer) VALUES ('x3:%lld',NULL,3,'da:a1:19:00:00:01',0,%lld,4,%lld,'','','');",
        T - 500, T - 500, T - 400);
    WT_EQ(sql_on(g_here_web, sql), 0);
    /* Two positions to measure between: beta's, and a peer no longer
     * named. */
    WT_EQ(sql_on(g_here_web, "UPDATE peer_sites SET lat=33.32919, lon=-111.87007,"
                             " pos_source='fixed' WHERE peer='beta';"
                             "INSERT INTO peer_sites (peer,url,lat,lon) VALUES"
                             " ('old','http://100.64.9.9:8770',41.8781136,-87.6297982);"), 0);

    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    m4.fleet = &F;
    m4.sdb = &here;
    m4.frrs = &fr2;
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T + 65;
    h.m4 = &m4;
    static char out[65536];
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    snprintf(rq.path, sizeof(rq.path), "/api/fleet/overview");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_HAS(out, "{\"local\":{\"name\":\"self\",\"label\":null,\"sloth_db\":\"open\",\"lat\":null,");
    WT_HAS(out, ",\"store\":true,\"configured\":1,\"peers\":[{\"name\":\"beta\",\"configured\":true,");
    WT_HAS(out, ",\"last_ok_age_s\":60,\"last_attempt_age_s\":60,\"last_error\":null,"
                "\"skew_s\":-5,");
    WT_HAS(out, ",\"counts\":{\"wifi\":9,\"ble\":0,\"ap\":0,\"probe\":2,");
    WT_HAS(out, "{\"name\":\"old\",\"configured\":false,");
    WT_HAS(out, "\"distances\":[{\"a\":\"beta\",\"b\":\"old\",\"m\":2326925.0}]");
    snprintf(rq.query, sizeof(rq.query), "x=1");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 400);

    snprintf(rq.path, sizeof(rq.path), "/api/fleet/shared");
    snprintf(rq.query, sizeof(rq.query), "kind=wifi");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 200);
    char *body = (char *)r.body_owned;
    WT_ASSERT(body != NULL);
    if (body) {
        char *t = realloc(body, r.body_len + 1);
        if (t) { body = t; body[r.body_len] = '\0'; }
        WT_HAS(body, "{\"kind\":\"wifi\",\"limit\":50,\"store\":true,\"local\":\"open\",");
        WT_HAS(body, "\"partial\":false,");
        WT_HAS(body, "{\"key\":\"da:a1:19:00:00:01\",\"addr\":\"da:a1:19:00:00:01\","
                     "\"label\":\"HomeNet\",\"vendor\":\"Apple\",\"last\":");
        WT_HAS(body, "\"sites\":[{\"site\":\"self\",\"first_seen\":1792626300,"
                     "\"last_seen\":1792627170,\"rssi\":-41},{\"site\":\"beta\",");
        WT_HAS(body, "\"verdict\":{\"state\":\"known\",\"site\":\"self\"}");
        /* No verdict here: the peer's, named with its site; and the
         * peer's at the address this site has triaged is not shown. */
        WT_HAS(body, "\"verdict\":{\"state\":\"incident\",\"site\":\"beta\"}");
        WT_LACKS(body, "\"state\":\"noise\"");
        /* Held by one site only: not listed. */
        WT_LACKS(body, "02:10:ca:10:ca:01");
        WT_LACKS(body, "da:a1:19:00:00:02");
        WT_LACKS(body, "00:11:22:33:44:55");
        /* The newest cross-site activity first. */
        const char *a = strstr(body, "\"key\":\"da:a1:19:00:00:01\"");
        const char *c = strstr(body, "\"key\":\"da:a1:19:00:00:04\"");
        WT_ASSERT(a && c && a < c);
        free(body);
    }
    snprintf(rq.query, sizeof(rq.query), "kind=wifi&limit=1");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    body = (char *)r.body_owned;
    if (body) {
        char *t = realloc(body, r.body_len + 1);
        if (t) { body = t; body[r.body_len] = '\0'; }
        WT_HAS(body, "da:a1:19:00:00:01");
        WT_LACKS(body, "da:a1:19:00:00:04");
        free(body);
    }
    snprintf(rq.query, sizeof(rq.query), "kind=probe");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    body = (char *)r.body_owned;
    if (body) {
        char *t = realloc(body, r.body_len + 1);
        if (t) { body = t; body[r.body_len] = '\0'; }
        WT_HAS(body, "{\"key\":\"da:a1:19:00:00:01|CafeFree\",\"addr\":\"da:a1:19:00:00:01\",");
        WT_LACKS(body, "HomeNet");
        WT_LACKS(body, "OnlyHere");
        free(body);
    }
    static const char *const badq[] = { "kind=alert", "kind=wifi&limit=0", "limit=201",
                                        "kind=wifi&x=1", "limit=1x" };
    for (size_t i = 0; i < sizeof(badq) / sizeof(badq[0]); i++) {
        snprintf(rq.query, sizeof(rq.query), "%s", badq[i]);
        WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
        WT_EQ(r.status, 400);
        free(r.body_owned);
    }
    web_frrs_destroy(&fr2);
    web_slothdb_destroy(&here);
    here_down(&srv, th);
}
#endif

void run_fleet_tests(void) {
    WT_RUN(test_peer_urls);
    WT_RUN(test_peer_flags);
    WT_RUN(test_members_are_not_secret);
#ifdef WITH_SQLITE
    WT_RUN(test_export_withholds_secrets);
    WT_RUN(test_export_since);
    WT_RUN(test_export_sends_only_what_the_importer_takes);
    WT_RUN(test_pull_good_and_upsert);
    WT_RUN(test_pull_refusals);
    WT_RUN(test_pull_trickle_is_cut_off);
    WT_RUN(test_pull_unreachable_and_thread);
    WT_RUN(test_export_pages);
    WT_RUN(test_backfill_after_a_cut);
    WT_RUN(test_backfill_alerts_past_the_scan);
    WT_RUN(test_pull_from_an_f1_peer);
    WT_RUN(test_overview_and_shared);
#endif
    WT_RUN(test_distance);
    WT_RUN(test_fleet_page);
}
