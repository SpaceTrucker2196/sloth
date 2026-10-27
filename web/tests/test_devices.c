/* The Devices and Lookup routes (#162, M4; web_devices.h) through the
 * route table, without a socket: a sloth.db generated from sloth's own
 * DDL (sdb_gen.c), the test's own OUI table, slothweb's store, rollup,
 * anomaly engine, identity tables and passive PTR cache, on the pinned
 * clock SDB_NOW. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_anomaly.h"
#include "web_assets.h"
#include "web_baseline.h"
#include "web_devices.h"
#include "web_ident.h"
#include "web_jsonl.h"
#include "web_ptr.h"
#include "web_routes.h"
#include "web_series.h"
#include "web_slothdb.h"
#include "web_store.h"
#include "web_tsdb.h"
#include "wtest.h"

static char g_out[65536];

static void req(web_req_t *rq, const char *path, const char *query, int head) {
    memset(rq, 0, sizeof(*rq));
    rq->is_head = head;
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query);
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
}

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static int route(const web_health_t *h, const char *path, const char *query,
                 int head) {
    web_req_t rq;
    web_resp_t r;
    req(&rq, path, query, head);
    if (web_route(&rq, h, 1, g_out, sizeof(g_out), &r) != 0) return -1;
    g_out[r.out_len] = '\0';
    return r.status;
}

/* No sloth.db: /api/devices says so; the drawer and Lookup answer from
 * the stream and the vendor table alone. And every path is still a
 * GET/HEAD-only route behind the Host check. A deeper path seen red
 * (a 400, not a 404) with web_route()'s '/' check removed. */
static void test_without_sloth_db(void) {
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = SDB_NOW;
    WT_EQ(route(&h, "/api/devices", "", 0), 503);
    WT_HAS(body_of(g_out), "{\"error\":\"no_sloth_db\"");
    web_m4_t m;
    memset(&m, 0, sizeof(m));
    m.oui = web_oui_builtin();
    h.m4 = &m;
    WT_EQ(route(&h, "/api/devices", "q=x", 0), 503);
    WT_EQ(route(&h, "/api/device/00%3A03%3A93%3A00%3A00%3A01", "", 0), 200);
    WT_HAS(body_of(g_out), "\"db\":\"none\"");
    WT_HAS(body_of(g_out), "\"record\":null");
    WT_EQ(route(&h, "/api/lookup", "q=00:03:93:00:00:01", 0), 200);
    WT_HAS(body_of(g_out), "\"active\":false");
    WT_HAS(body_of(g_out), "\"device\":null");
    static const char *const methods[] = { "POST", "PUT", "DELETE", "PATCH" };
    static const char *const paths[] = { "/api/devices", "/api/lookup",
                                         "/api/device/00:03:93:00:00:01" };
    for (size_t i = 0; i < 4; i++)
        for (size_t k = 0; k < 3; k++) {
            char rqs[256];
            snprintf(rqs, sizeof(rqs), "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                     "Content-Length: 0\r\n\r\n", methods[i], paths[k]);
            int hd;
            WT_EQ(web_http_classify(rqs, strlen(rqs), &hd), 405);
        }
    for (size_t k = 0; k < 3; k++) {
        web_req_t rq;
        web_resp_t r;
        req(&rq, paths[k], "", 0);
        snprintf(rq.host, sizeof(rq.host), "attacker.example");
        WT_EQ(web_route(&rq, &h, 1, g_out, sizeof(g_out), &r), 0);
        WT_EQ(r.status, 421);
    }
    /* /api/device/ alone, or a deeper path, is not a device. */
    WT_EQ(route(&h, "/api/device/", "", 0), 404);
    WT_EQ(route(&h, "/api/device/00:03:93:00:00:01/x", "", 0), 404);
    WT_EQ(route(&h, "/api/devices/", "", 0), 404);
}

/* The M4 page: the elements app.js draws into and the fetches it makes,
 * both halves of each name (the HTML's id and the script's lookup of
 * it), as the served page carries them; the shapes those fetches build
 * are answered 200 below (test_page_fetch_shapes). Each seen red with
 * the id renamed in index.html (d-rows), and with the fetch prefix
 * misspelt in app.js (/api/device/). */
static void test_page_carries_the_m4_views(void) {
    const char *p = (const char *)web_page;
    static const char *const ids[] = {
        "v-devices", "v-lookup", "nav-devices", "nav-lookup", "d-q", "d-sort",
        "d-rows", "d-scroll", "d-space", "d-count", "d-note", "drawer", "dr-body",
        "dr-strip", "dr-week", "dr-anoms", "dr-close", "dr-mac", "l-q", "l-go",
        "l-card", "l-src",
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        char want[64];
        snprintf(want, sizeof(want), "id=\"%s\"", ids[i]);
        WT_HAS(p, want);
        if (i < 2) continue;                      /* looked up as "v-" + view */
        /* $("id") or set("id", ...), which looks it up the same way. */
        char alt[64];
        snprintf(want, sizeof(want), "$(\"%s\")", ids[i]);
        snprintf(alt, sizeof(alt), "set(\"%s\",", ids[i]);
        if (!strstr(p, want) && !strstr(p, alt))
            fprintf(stderr, "    no lookup of %s\n", ids[i]);
        WT_ASSERT(strstr(p, want) || strstr(p, alt));
    }
    WT_HAS(p, "var VIEWS = [\"overview\", \"activity\", \"devices\", \"anomalies\", \"wifi\", \"flows\", \"history\",\n"
              "               \"lookup\"];");
    WT_HAS(p, "var p = \"/api/devices?limit=\" + DEV_PAGE + \"&offset=\" + offset +\n"
              "            \"&sort=\" + encodeURIComponent(sort);");
    WT_HAS(p, "if (q !== \"\") p += \"&q=\" + encodeURIComponent(q);");
    WT_HAS(p, "getJSON(\"/api/device/\" + encodeURIComponent(mac))");
    WT_HAS(p, "getJSON(\"/api/lookup?q=\" + encodeURIComponent(q))");
    /* A drawer opens only for a canonical MAC, from a row or a card. */
    WT_HAS(p, "var MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;");
    WT_HAS(p, "if (typeof mac !== \"string\" || !MAC_RE.test(mac)) return;");
    WT_HAS(p, "if (typeof a.key === \"string\" && MAC_RE.test(a.key)) {");
    /* The two ways in (#162): a card's click and a row's. Each seen red
     * with its line removed from app.js. */
    WT_HAS(p, "c.addEventListener(\"click\", function () { openDrawer(a.key); });");
    WT_HAS(p, "r.el.addEventListener(\"click\", function () { if (r.mac) openDrawer(r.mac); });");
    /* No active lookup anywhere on the page (the 2026-10-21 ruling). */
    WT_LACKS(p, "ACTIVE QUERY");
    WT_LACKS(p, "active-rdns");
    WT_HAS(p, "<span id=\"milestone\">M6</span>");
}


/* #168: every DB-backed view (Devices, WiFi's AP table, Flows, History,
 * Lookup) carries the freshness line, and the page fills it from
 * /api/health, in the warning style when the server says stale. Seen
 * red with h-dbage renamed in index.html, with the stale class dropped
 * from dbAge() in app.js, and with the .dbage.stale rule removed from
 * page.css. */
static void test_page_shows_db_freshness(void) {
    const char *p = (const char *)web_page;
    static const char *const ids[] = {
        "d-dbage", "w-dbage", "f-dbage", "h-dbage", "l-dbage",
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        char want[96];
        snprintf(want, sizeof(want), "<span class=\"sub dbage\" id=\"%s\"></span>", ids[i]);
        WT_HAS(p, want);
    }
    WT_HAS(p, "var DB_VIEWS = [\"devices\", \"wifi\", \"flows\", \"history\", \"lookup\"];");
    WT_HAS(p, "var DB_AGE_IDS = [\"d-dbage\", \"w-dbage\", \"f-dbage\", \"h-dbage\", \"l-dbage\"];");
    WT_HAS(p, "var t = \"database as of \" + dbWhen(h.sloth_db_mtime);");
    /* The date when it is not today's (a days-old snapshot with the
     * stream down is not "stale" and must not read as today). Seen red
     * with the date line removed from dbWhen(). */
    WT_HAS(p, "if (d.toDateString() === now.toDateString()) return t;\n"
              "    return d.getFullYear() + \"-\" + two(d.getMonth() + 1) + \"-\" + two(d.getDate()) + \" \" + t;");
    WT_HAS(p, "if (h.sloth_db_stale === true)\n"
              "      t += \" - stale: \" + dur(h.sloth_db_age_s) + \" old while the live stream is current; these rows are as old as it is\";");
    WT_HAS(p, "e.className = stale ? \"sub dbage stale\" : \"sub dbage\";");
    WT_HAS(p, ".dbage.stale { color: var(--sev-warn); font-weight: bold; }");
    /* Filled at load, on showing a DB-backed view, and every 30 s while
     * one is shown. */
    WT_HAS(p, "      dbAge(h);\n");
    WT_HAS(p, "if (DB_VIEWS.indexOf(v) >= 0) dbFresh();");
    WT_HAS(p, "setInterval(function () { if (DB_VIEWS.indexOf(view) >= 0) dbFresh(); }, 30000);");
}

#ifdef WITH_SQLITE

static char g_dir[64];
static oui_build_t g_oui;
static web_slothdb_t g_sdb;
static web_store_t g_store;
static web_rollup_t g_ru;
static web_tsdb_t g_ts;
static web_baseline_t g_bl;
static web_ident_t g_id;
static web_anomaly_t g_an;
static web_ptr_t g_ptr;
static web_m4_t g_m4;
static web_health_t H;
static char g_db[128];

static void feed(const char *line, long long now) {
    static web_jrec_t r;
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_ident_record(&g_id, &r, now);
}

static void up(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/slothweb-dev-XXXXXX");
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    WT_EQ(sdb_oui(&g_oui, g_dir), 0);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, db_schema_version(), 1), 0);
    WT_EQ(sdb_seed(g_db), 0);
    char sp[128], err[512];
    snprintf(sp, sizeof(sp), "%s/slothweb.db", g_dir);
    WT_EQ(web_store_open(&g_store, sp, err, sizeof(err)), 0);
    WT_EQ(web_rollup_init(&g_ru, 64, 1, err, sizeof(err)), 0);
    WT_EQ(web_tsdb_init(&g_ts, &g_ru, &g_store, 30, 256, NULL, NULL), 0);
    WT_EQ(web_baseline_init(&g_bl, 256), 0);
    WT_EQ(web_ident_init(&g_id, 64, 64), 0);
    WT_EQ(web_ptr_init(&g_ptr, 16), 0);
    web_ident_set_ptr(&g_id, &g_ptr);
    web_anom_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.bl = &g_bl;
    c.store = &g_store;
    c.ident = &g_id;
    c.max_keys = 64;
    c.oui = &g_oui.tab;
    c.ptr = &g_ptr;
    WT_EQ(web_anomaly_init(&g_an, 64, &c), 0);
    web_sdb_fns_t f = { &g_oui.tab, &g_an, &g_ptr, NULL };
    web_slothdb_init(&g_sdb, g_db, &f);
    g_m4.sdb = &g_sdb;
    g_m4.oui = &g_oui.tab;
    g_m4.ptr = &g_ptr;
    g_m4.ident = &g_id;
    g_m4.anomaly = &g_an;
    g_m4.tsdb = &g_ts;
    memset(&H, 0, sizeof(H));
    H.wall_s = SDB_NOW;
    H.m4 = &g_m4;
    H.tsdb = &g_ts;
    H.anomaly = &g_an;
    /* D8's address has a PTR answer seen on the wire. */
    web_ptr_record(&g_ptr, "PTR", 1, "18.1.0.10.in-addr.arpa", "sensor.lan",
                   SDB_NOW - 30);
}

static void down(void) {
    web_slothdb_destroy(&g_sdb);
    web_anomaly_destroy(&g_an);
    web_ptr_destroy(&g_ptr);
    web_ident_destroy(&g_id);
    web_baseline_destroy(&g_bl);
    web_tsdb_destroy(&g_ts);
    web_rollup_destroy(&g_ru);
    web_store_close(&g_store);
    oui_build_free(&g_oui);
    char p[192];
    const char *files[] = { "sloth.db", "sloth.db-wal", "sloth.db-shm",
                            "slothweb.db", "slothweb.db-wal", "slothweb.db-shm" };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        snprintf(p, sizeof(p), "%s/%s", g_dir, files[i]);
        unlink(p);
    }
    rmdir(g_dir);
}

/* The MACs of a /api/devices body, in order. */
static void macs_of(const char *b, char *out, size_t cap) {
    size_t o = 0;
    out[0] = '\0';
    for (const char *p = b; (p = strstr(p, "{\"mac\":\"")); p += 8) {
        const char *q = strchr(p + 8, '"');
        if (!q) break;
        o += (size_t)snprintf(out + o, cap - o, "%s%.*s", o ? " " : "",
                              (int)(q - p - 8), p + 8);
    }
}

/* Spec §12, M4, over HTTP: the query as the page sends it (form-encoded
 * by encodeURIComponent, '+' a space). */
static void test_devices_acceptance(void) {
    char macs[512];
    WT_EQ(route(&H, "/api/devices",
                "q=vendor%3Aapple%20random%3Ayes%20seen%3A%3C24h", 0), 200);
    const char *b = body_of(g_out);
    macs_of(b, macs, sizeof(macs));
    WT_ASSERT(!strcmp(macs, "da:a1:19:00:00:01 f2:11:22:00:00:06"));
    WT_HAS(b, "\"count\":2,\"more\":false,\"next_offset\":null}");
    WT_HAS(b, "\"q\":\"vendor:apple random:yes seen:\\u003c24h\"");
    WT_HAS(b, "\"vendor_table\":\"ieee\"");
    WT_EQ(route(&H, "/api/devices", "q=vendor:apple+random:yes+seen:<24h", 0), 200);
    macs_of(body_of(g_out), macs, sizeof(macs));
    WT_ASSERT(!strcmp(macs, "da:a1:19:00:00:01 f2:11:22:00:00:06"));
    WT_HAS(g_out, "Content-Type: application/json\r\n");
    WT_HAS(g_out, "Cache-Control: no-store\r\n");
    /* HEAD: the headers, no body. */
    size_t full = strlen(g_out);
    WT_EQ(route(&H, "/api/devices", "q=vendor:apple+random:yes+seen:<24h", 1), 200);
    WT_ASSERT(strlen(g_out) < full);
    WT_EQ(strlen(body_of(g_out)), 0);
}

/* The credential's username is in an alert's key (sloth keys a
 * cleartext credential by it), and the key is read only as a predicate:
 * no body names it, the device list matched on it included. The D3 row
 * shows the key match itself still works. */
static void test_no_body_names_the_alert_key(void) {
    static const char *const qs[][2] = {
        { "", NULL }, { "q=has:alert", "00:03:93:00:00:03" }, { "q=alice", NULL },
        { "q=name:alice", NULL }, { "q=has:alert&sort=risk", "00:11:22:33:44:55" },
    };
    for (size_t i = 0; i < sizeof(qs) / sizeof(qs[0]); i++) {
        WT_EQ(route(&H, "/api/devices", qs[i][0], 0), 200);
        const char *b = body_of(g_out);
        WT_LACKS(b, "secret-user");             /* "q" echoes "alice" */
        WT_LACKS(b, "cred:");
        WT_LACKS(b, "evil_twin");
        if (qs[i][1]) WT_HAS(b, qs[i][1]);
    }
    static const char *const macs[] = {
        "/api/device/00%3A11%3A22%3A33%3A44%3A55", "/api/device/00%3A03%3A93%3A00%3A00%3A03",
    };
    for (size_t i = 0; i < sizeof(macs) / sizeof(macs[0]); i++) {
        WT_EQ(route(&H, macs[i], "", 0), 200);
        const char *b = body_of(g_out);
        WT_LACKS(b, "alice");
        WT_LACKS(b, "cred:");
        WT_LACKS(b, "evil_twin");
    }
    WT_HAS(body_of(g_out), "\"title\":\"Evil twin\"");   /* by its key */
    WT_EQ(route(&H, "/api/lookup", "q=00:11:22:33:44:55", 0), 200);
    WT_LACKS(body_of(g_out), "alice");
    WT_LACKS(body_of(g_out), "cred:");
}

/* One row's members, the vendor's source, the names' glyphs. Markup
 * seen red (a raw <b>) with jw_text_or_null() writing the text raw. */
static void test_device_rows(void) {
    WT_EQ(route(&H, "/api/devices", "q=mac:da:a1:19:00:00:01", 0), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"mac\":\"da:a1:19:00:00:01\",\"random\":true,\"vendor\":\"Apple\","
              "\"vendor_src\":\"sloth\",\"ip\":\"10.0.1.11\",\"name\":null,"
              "\"name_src\":null,\"ssid\":\"HomeNet\",\"signal\":-48,"
              "\"sources\":48,\"is_ap\":false,\"risk\":1,\"risk_signals\":1,");
    WT_HAS(b, "\"z\":null,\"anomalies\":0,\"presence\":\"");
    /* The MA-S device: the vendor from the IEEE table, its name from a
     * PTR answer seen on the wire. */
    WT_EQ(route(&H, "/api/devices", "q=mac:70:b3", 0), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"vendor\":\"Small Vendor Ltd\",\"vendor_src\":\"oui\"");
    WT_HAS(b, "\"name\":\"sensor.lan\",\"name_src\":\"p\"");
    /* D9: DHCP first among its names; its markup hostname is not shown
     * as markup anywhere. */
    WT_EQ(route(&H, "/api/devices", "q=name:%3Cb%3E", 0), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"mac\":\"00:11:22:33:44:55\"");
    WT_HAS(b, "\"name\":\"nas-dhcp\",\"name_src\":\"D\"");
    WT_LACKS(g_out, "<b>");
    WT_EQ(route(&H, "/api/device/00:11:22:33:44:55", "", 0), 200);
    WT_LACKS(g_out, "<b>");
    WT_HAS(g_out, "\\u003cb\\u003enas\\u003c/b\\u003e");
}

/* Paging, the cap, and every refusal of the query string. The value
 * never comes back: seen red with the parse error answered with the q
 * value as its detail. */
static void test_devices_paging_and_refusals(void) {
    char a[512], b2[512];
    WT_EQ(route(&H, "/api/devices", "sort=mac&limit=4", 0), 200);
    WT_HAS(body_of(g_out), "\"count\":4,\"more\":true,\"next_offset\":4}");
    macs_of(body_of(g_out), a, sizeof(a));
    WT_EQ(route(&H, "/api/devices", "sort=mac&limit=4&offset=4", 0), 200);
    macs_of(body_of(g_out), b2, sizeof(b2));
    WT_ASSERT(strcmp(a, b2) && a[0] && b2[0]);
    WT_EQ(route(&H, "/api/devices", "sort=mac&limit=4&offset=8", 0), 200);
    WT_HAS(body_of(g_out), "\"count\":1,\"more\":false");
    static const char *const bad[][2] = {
        { "limit=0", "bad_limit" }, { "limit=201", "bad_limit" },
        { "limit=x", "bad_limit" }, { "offset=100001", "bad_offset" },
        { "offset=-1", "bad_offset" }, { "sort=rowid", "bad_sort" },
        { "x=1", "unknown_parameter" }, { "q=a&q=b", "repeated_parameter" },
        { "q=", "empty_value" }, { "q=%zz", "bad_escape" }, { "q", "bad_query" },
        { "q=mac:zz", "bad_mac" }, { "q=%0a", "bad_value" },
        { "q=z:%3D3", "bad_z" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int st = route(&H, "/api/devices", bad[i][0], 0);
        if (st != 400 || !strstr(body_of(g_out), bad[i][1]))
            fprintf(stderr, "    %s -> %d %s\n", bad[i][0], st, body_of(g_out));
        WT_EQ(st, 400);
        WT_HAS(body_of(g_out), bad[i][1]);
        WT_LACKS(body_of(g_out), "zz");          /* never the value back */
    }
    web_req_t rq;
    web_resp_t r;
    req(&rq, "/api/devices", "", 0);
    rq.query_long = 1;
    WT_EQ(web_route(&rq, &H, 1, g_out, sizeof(g_out), &r), 0);
    WT_EQ(r.status, 400);
}

/* sloth.db missing, refused or newer: a 503 naming the reader's state,
 * never a 500 or a guess. */
static void test_devices_db_states(void) {
    web_slothdb_t s;
    char p[160];
    snprintf(p, sizeof(p), "%s/none.db", g_dir);
    web_slothdb_init(&s, p, NULL);
    web_m4_t m = g_m4;
    m.sdb = &s;
    web_health_t h = H;
    h.m4 = &m;
    WT_EQ(route(&h, "/api/devices", "", 0), 503);
    WT_HAS(body_of(g_out), "\"error\":\"sloth_db_missing\"");
    WT_HAS(body_of(g_out), "not there");
    WT_EQ(route(&h, "/api/device/00:11:22:33:44:55", "", 0), 200);
    WT_HAS(body_of(g_out), "\"db\":\"missing\"");
    web_slothdb_destroy(&s);
}

/* The drawer: the record, its lists, the strip, the week, anomalies,
 * alerts. The path may be percent-encoded, upper case or dashed. The
 * group name seen red with web_sdb_names()'s suffix filter removed. The
 * credential's absence has two layers, the statements (none names a
 * column holding it) and the authorizer (which would refuse one); no
 * single edit shows it red, and the authorizer's half is
 * test_authorizer_denies's. */
static void test_device_drawer(void) {
    WT_EQ(route(&H, "/api/device/DA-A1-19-00-00-01", "", 0), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"mac\":\"da:a1:19:00:00:01\",\"now\":1792627200,\"db\":\"open\"");
    WT_HAS(b, "\"record\":{\"mac\":\"da:a1:19:00:00:01\"");
    WT_HAS(b, "\"detail\":{\"hostname\":null,\"device_class\":0");
    WT_HAS(b, "\"ssids\":[{\"ssid\":\"HomeNet\"");
    WT_HAS(b, "{\"ssid\":\"CafeFree\"");
    WT_HAS(b, "\"ssids_more\":false");
    WT_HAS(b, "\"assocs\":[{\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"ssid\":\"HomeNet\","
              "\"source\":1,\"channel\":6,\"signal\":-50");
    WT_HAS(b, "\"week\":{\"now_cell\":");
    WT_HAS(b, "\"cells\":null");
    WT_HAS(b, "\"anomalies\":[]");
    WT_HAS(b, "\"oui\":{\"found\":false");
    WT_HAS(b, "\"local\":true");
    WT_EQ(route(&H, "/api/device/00%3A11%3A22%3A33%3A44%3A55", "", 0), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"alerts\":[{\"title\":\"FTP login in cleartext\",\"type\":12,"
              "\"sev\":2,\"count\":3");
    WT_HAS(b, "{\"name\":\"nas-dhcp\",\"src\":\"dhcp\",\"where\":\"sloth.db\"");
    WT_HAS(b, "{\"name\":\"NAS\",\"src\":\"nbns\"");
    WT_LACKS(b, "WORKGROUP");                   /* a group name */
    WT_LACKS(b, "alice");                       /* the credential, nowhere */
    WT_HAS(b, "\"ips\":[{\"addr\":\"10.0.1.5\"");
    WT_HAS(b, "\"oui\":{\"found\":true,\"vendor\":\"Generic Corp\"");
    /* A MAC sloth.db does not hold: the vendor card and the stream. */
    WT_EQ(route(&H, "/api/device/00:03:93:aa:bb:cc", "", 0), 200);
    WT_HAS(body_of(g_out), "\"record\":null");
    WT_HAS(body_of(g_out), "\"vendor\":\"Apple, Inc.\"");
    static const char *const bad[] = {
        "/api/device/zz", "/api/device/00:11:22:33:44", "/api/device/%zz",
        "/api/device/00:11:22:33:44:55:66", "/api/device/00%3A00%3A00%3A00%3A00%3A00",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        WT_EQ(route(&H, bad[i], "", 0), 400);
    WT_EQ(route(&H, "/api/device/00:11:22:33:44:55", "x=1", 0), 400);
}

/* The drawer's strip and week, and its episodes: presence from the
 * store's minute tier and the in-memory ring, cells from the baseline,
 * an open episode keyed by the MAC. */
static void test_drawer_presence_week_anomalies(void) {
    const char *mac = "da:a1:19:00:00:01";
    long long from = SDB_NOW - SDB_NOW % 600 - 143 * 600;
    /* The store: a minute row in cell 1. */
    web_qrow_t q;
    memset(&q, 0, sizeof(q));
    q.tier = WEB_TIER_MINUTE;
    q.metric = WM_DEV_PRESENT;
    snprintf(q.key, sizeof(q.key), "%s", mac);
    q.t = from + 600;
    q.sum = q.min = q.max = 1;
    q.n = 1;
    WT_EQ(web_store_write(&g_store, &q, 1), 0);
    /* The ring: a 10 s bucket in the last cell, closed by the next. */
    web_rollup_add(&g_ru, WM_DEV_PRESENT, mac, 1, SDB_NOW - 30);
    web_rollup_add(&g_ru, WM_DEV_PRESENT, mac, 1, SDB_NOW - 15);
    WT_EQ(route(&H, "/api/device/da:a1:19:00:00:01", "", 0), 200);
    const char *b = body_of(g_out);
    /* Cell 1 is the second bit of the first digit (4). SDB_NOW starts
     * the last cell (143), so SDB_NOW - 30 is in cell 142: the third
     * bit of the last digit (2). */
    WT_HAS(b, "\"presence\":\"400000000000000000000000000000000002\"");
    /* The week: a fed cell at its index. */
    web_baseline_feed(&g_bl, WM_DEV_PRESENT, mac, SDB_NOW - 3600, 1, 1);
    web_store_ep_t e;
    memset(&e, 0, sizeof(e));
    e.id = 77;
    snprintf(e.kind, sizeof(e.kind), "A3");
    e.metric = WM_DEV_PRESENT;
    snprintf(e.key, sizeof(e.key), "%s", mac);
    e.state = WEB_EP_OPEN;
    e.score = e.peak = 70;
    snprintf(e.evidence, sizeof(e.evidence), "off hours");
    e.first_seen = SDB_NOW - 120;
    e.last_seen = SDB_NOW - 60;
    e.last_bucket = SDB_NOW - 120;
    web_anomaly_restore_episode(&g_an, &e);
    WT_EQ(route(&H, "/api/device/da:a1:19:00:00:01", "", 0), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"cells\":[[");
    WT_HAS(b, "\"anomalies\":[{\"id\":77,\"rule\":\"A3\",\"kind\":\"hours\"");
    /* And the list's count, and the anomaly: and has: terms. */
    WT_EQ(route(&H, "/api/devices", "q=anomaly:hours", 0), 200);
    char macs[256];
    macs_of(body_of(g_out), macs, sizeof(macs));
    WT_ASSERT(!strcmp(macs, mac));
    WT_HAS(body_of(g_out), "\"anomalies\":1,");
    WT_EQ(route(&H, "/api/devices", "q=has:anomaly+-anomaly:rate", 0), 200);
    macs_of(body_of(g_out), macs, sizeof(macs));
    WT_ASSERT(!strcmp(macs, mac));
}

/* The Lookup card (§8.11, without the active part, ever): a MAC from an
 * MA-S block resolves to its holder where sloth's own 117-entry table
 * has nothing (spec §12, M4), with its block, registry and bits; an IP
 * gives its ARP MAC, every passive name and its sloth.db record. */
static void test_lookup(void) {
    WT_EQ(route(&H, "/api/lookup", "q=70:B3:D5:F2:A1:23", 0), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"kind\":\"mac\"");
    WT_HAS(b, "\"oui\":{\"found\":true,\"vendor\":\"Small Vendor Ltd\","
              "\"block\":\"70:b3:d5:f2:a\",\"bits\":36,\"registry\":\"MA-S\","
              "\"private\":false,\"local\":false,\"multicast\":false,"
              "\"table\":\"ieee\",\"full\":true}");
    WT_HAS(b, "\"device\":{\"mac\":\"70:b3:d5:f2:a1:23\"");
    WT_HAS(b, "{\"name\":\"sensor.lan\",\"src\":\"ptr\",\"where\":\"wire\"");
    WT_HAS(b, "\"active\":false");
    /* The same MAC against sloth's own table: no vendor. */
    oui_build_t sl;
    oui_build_init(&sl);
    WT_EQ(oui_build_sloth(&sl, "src/oui.c"), 0);
    WT_EQ(oui_build_finish(&sl, "sloth"), 0);
    web_m4_t m = g_m4;
    m.oui = &sl.tab;
    web_health_t h = H;
    h.m4 = &m;
    WT_EQ(route(&h, "/api/lookup", "q=70:b3:d5:f2:a1:23", 0), 200);
    WT_HAS(body_of(g_out), "\"oui\":{\"found\":false,\"vendor\":null");
    WT_HAS(body_of(g_out), "\"table\":\"sloth\",\"full\":false");
    oui_build_free(&sl);
    /* An IP. */
    feed("{\"type\":\"mdns_service\",\"ts\":1,\"ip\":\"10.0.1.5\",\"host\":"
         "\"nas-stream.local\",\"instance\":\"x\"}", SDB_NOW);
    WT_EQ(route(&H, "/api/lookup", "q=10.0.1.5", 0), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"kind\":\"ip\"");
    WT_HAS(b, "\"oui\":null");
    WT_HAS(b, "\"macs\":[{\"addr\":\"00:11:22:33:44:55\"");
    WT_HAS(b, "{\"name\":\"nas-stream.local\",\"src\":\"mdns\",\"where\":\"stream\"");
    WT_HAS(b, "\"device\":{\"mac\":\"00:11:22:33:44:55\"");
    WT_LACKS(b, "alice");
    static const char *const bad[][2] = {
        { "", "missing_q" }, { "q=nas", "bad_lookup" }, { "q=10.0.1", "bad_lookup" },
        { "q=1&q=2", "repeated_parameter" }, { "ip=10.0.0.1", "unknown_parameter" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        WT_EQ(route(&H, "/api/lookup", bad[i][0], 0), 400);
        WT_HAS(body_of(g_out), bad[i][1]);
    }
}

/* /api/health's M4 members. */
static void test_health_members(void) {
    WT_EQ(route(&H, "/api/health", "", 0), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"milestone\":\"M6\"");
    WT_HAS(b, "\"db\":\"open\",\"db_schema\":8,\"db_rows\":9,\"db_path\":");
    WT_HAS(b, "\"db_mode\":\"immutable\"");
    WT_HAS(b, "\"db_supported\":[1,8]");
    WT_HAS(b, "\"vendor_table\":\"ieee\",\"vendor_counts\":{\"ma_l\":3,"
              "\"ma_m\":0,\"ma_s\":1}");
    WT_HAS(b, "\"a4\":\"on\"");
    WT_HAS(b, "\"passive_ptr\":{\"entries\":1,\"cap\":16,\"seen\":1,\"stored\":1,");
}

/* #168: what the DB-backed views are as of, and when the page calls
 * that stale. g_db is a WAL file closed cleanly, read immutable, so its
 * own mtime is the data's. Stale needs both halves: older than
 * WEB_SDB_STALE_S, and a stream that is current. The two "false" cases
 * with an old file (no stream, a stream gone quiet) were seen red with
 * the stream condition dropped from web_sdb_is_stale(); the boundary
 * (600 s, false) with its ">" made ">=". */
static void db_mtime_at(long long t) {
    struct timespec ts[2];
    ts[0].tv_sec = (time_t)t; ts[0].tv_nsec = 0;
    ts[1] = ts[0];
    WT_EQ(utimensat(AT_FDCWD, g_db, ts, 0), 0);
}

static void health_has(const char *want) {
    WT_EQ(route(&H, "/api/health", "", 0), 200);
    const char *b = body_of(g_out);
    if (!strstr(b, want)) fprintf(stderr, "    want %s in\n    %s\n", want, b);
    WT_HAS(b, want);
}

static void test_health_db_freshness(void) {
    WT_EQ(web_sdb_is_stale(601, 1), 1);
    WT_EQ(web_sdb_is_stale(600, 1), 0);
    WT_EQ(web_sdb_is_stale(86400, 0), 0);
    WT_EQ(web_sdb_is_stale(-1, 1), 0);

    db_mtime_at(SDB_NOW - 700);
    /* No data socket: the age is said, but it is not "stale". */
    health_has("\"db_mode\":\"immutable\",\"sloth_db_mtime\":1792626500,"
               "\"sloth_db_age_s\":700,");
    health_has("\"sloth_db_stale_after_s\":600,\"sloth_db_stale\":false");

    web_live_t lv;
    web_live_init(&lv, "unix:/run/sloth/sloth.sock");
    H.live = &lv;
    H.now_ms = 1000000;
    web_live_sock_connected(&lv, H.now_ms - 5000);
    static web_jrec_t r;
    static const char rec[] = "{\"type\":\"heartbeat\",\"ts\":1792627190}";
    WT_EQ(web_jl_parse(rec, strlen(rec), &r), WEB_JL_OK);
    web_live_apply(&lv, &r, H.now_ms - 2000);
    health_has("\"sloth_db_stale\":true");

    /* The stream gone quiet as well: that is the socket's message. */
    H.now_ms += (WEB_SDB_STREAM_CURRENT_S + 1) * 1000LL;
    health_has("\"sloth_db_stale\":false");
    H.now_ms -= (WEB_SDB_STREAM_CURRENT_S + 1) * 1000LL;

    db_mtime_at(SDB_NOW - WEB_SDB_STALE_S);
    health_has("\"sloth_db_age_s\":600,");
    health_has("\"sloth_db_stale\":false");
    db_mtime_at(SDB_NOW - WEB_SDB_STALE_S - 1);
    health_has("\"sloth_db_stale\":true");
    db_mtime_at(SDB_NOW - 30);
    health_has("\"sloth_db_age_s\":30,");
    health_has("\"sloth_db_stale\":false");
    /* A clock behind the file's: 0, not negative. */
    db_mtime_at(SDB_NOW + 100);
    health_has("\"sloth_db_mtime\":1792627300,\"sloth_db_age_s\":0,");

    H.live = NULL;
    H.now_ms = 0;
    web_live_destroy(&lv);
}

/* A file that is not open has no age, and says so with null. */
static void test_health_db_freshness_unknown(void) {
    web_slothdb_t s;
    web_m4_t m = g_m4;
    char p[192];
    snprintf(p, sizeof(p), "%s/absent.db", g_dir);
    web_slothdb_init(&s, p, NULL);
    m.sdb = &s;
    web_health_t h = H;
    h.m4 = &m;
    WT_EQ(route(&h, "/api/health", "", 0), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"db\":\"missing\"");
    WT_HAS(b, "\"sloth_db_mtime\":null,\"sloth_db_age_s\":null");
    WT_HAS(b, "\"sloth_db_stale\":null");
    web_slothdb_destroy(&s);
}

/* The worst case: rows whose every text member is at its cut length and
 * escapes six-fold. The page stops early with "more" rather than not
 * fit; nothing is a 503. Seen red with the room check in
 * web_devices_route() removed (a 503 at the 64 KB buffer). */
static void test_devices_worst_case_fits(void) {
    char p[160];
    snprintf(p, sizeof(p), "%s/worst.db", g_dir);
    WT_EQ(sdb_make(p, db_schema_version(), 0), 0);
    char lt[64 * 4 + 1];
    lt[0] = '\0';
    for (int i = 0; i < 63; i++) strcat(lt, "<");
    static char sql[1 << 16];
    size_t o = (size_t)snprintf(sql, sizeof(sql), "INSERT INTO devices (mac,ip,"
                                "hostname,vendor,last_ssid,first_seen,last_seen)"
                                " VALUES ");
    for (int i = 0; i < 200; i++)
        o += (size_t)snprintf(sql + o, sizeof(sql) - o,
                              "%s('aa:00:00:00:%02x:%02x','1111:2222:3333:4444:5555:"
                              "6666:7777:8888','%s','%s','%s',1,%d)",
                              i ? "," : "", i / 256, i % 256, lt, lt, lt, 1000 + i);
    WT_EQ(sdb_exec(p, sql), 0);
    web_slothdb_t s;
    web_sdb_fns_t f = { &g_oui.tab, &g_an, &g_ptr, NULL };
    web_slothdb_init(&s, p, &f);
    web_m4_t m = g_m4;
    m.sdb = &s;
    web_health_t h = H;
    h.m4 = &m;
    WT_EQ(route(&h, "/api/devices", "limit=200", 0), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"more\":true,\"next_offset\":");
    WT_ASSERT(strlen(g_out) < sizeof(g_out));
    int shown = 0;
    for (const char *q = b; (q = strstr(q, "{\"mac\":")); q++) shown++;
    WT_ASSERT(shown >= 20 && shown < 200);
    char want[64];
    snprintf(want, sizeof(want), "\"count\":%d,\"more\":true,\"next_offset\":%d}",
             shown, shown);
    WT_HAS(b, want);
    WT_EQ(route(&h, "/api/device/aa:00:00:00:00:07", "", 0), 200);
    web_slothdb_destroy(&s);
    unlink(p);
}

/* The query shapes the page's fetches build, answered 200. */
static void test_page_fetch_shapes(void) {
    static const char *const q[][2] = {
        { "/api/devices", "limit=200&offset=0&sort=last" },
        { "/api/devices", "limit=200&offset=200&sort=risk&q=vendor%3Aapple%20random%3Ayes%20seen%3A%3C24h" },
        { "/api/device/da%3Aa1%3A19%3A00%3A00%3A01", "" },
        { "/api/lookup", "q=70%3Ab3%3Ad5%3Af2%3Aa1%3A23" },
        { "/api/lookup", "q=10.0.1.5" },
    };
    for (size_t i = 0; i < sizeof(q) / sizeof(q[0]); i++)
        WT_EQ(route(&H, q[i][0], q[i][1], 0), 200);
}

void run_devices_tests(void) {
    WT_RUN(test_without_sloth_db);
    WT_RUN(test_page_carries_the_m4_views);
    WT_RUN(test_page_shows_db_freshness);
    up();
    WT_RUN(test_page_fetch_shapes);
    WT_RUN(test_devices_acceptance);
    WT_RUN(test_no_body_names_the_alert_key);
    WT_RUN(test_device_rows);
    WT_RUN(test_devices_paging_and_refusals);
    WT_RUN(test_devices_db_states);
    WT_RUN(test_device_drawer);
    WT_RUN(test_drawer_presence_week_anomalies);
    WT_RUN(test_lookup);
    WT_RUN(test_health_members);
    WT_RUN(test_health_db_freshness);
    WT_RUN(test_health_db_freshness_unknown);
    WT_RUN(test_devices_worst_case_fits);
    down();
}

#else

void run_devices_tests(void) {
    WT_RUN(test_without_sloth_db);
    WT_RUN(test_page_carries_the_m4_views);
    WT_RUN(test_page_shows_db_freshness);
}

#endif
