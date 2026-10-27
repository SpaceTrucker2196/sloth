/* Sortable, resizable columns on every table of the page (owner request
 * 2026-10-26): the server-paged routes' sort words and dir=asc|desc,
 * checked against their lists and compiled from constants only, the
 * order they give over a generated sloth.db; and the page's one table
 * implementation, its ids and its use by every table. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_assets.h"
#include "web_query.h"
#include "web_routes.h"
#include "web_store.h"
#include "web_tsdb.h"
#include "wtest.h"

#define T SDB_NOW

/* The compiled statement: a direction changes only the ORDER BY, from
 * the sort's own constant column, empty last; no direction leaves the
 * statement exactly as it was; an address sorts by its numeric key.
 * Seen red with the KEY table's ip entry pointing at d.hostname. */
static void test_dir_compiles_from_constants(void) {
    web_query_t q;
    memset(&q, 0, sizeof(q));
    web_qsql_t s;
    WT_EQ(web_query_compile(&q, 0, WEB_SORT_PACK(WEB_QS_IP, WEB_SORT_ASC), 10, 0, &s), 0);
    WT_HAS(s.sql, " ORDER BY web_ipkey(d.ip) IS NULL, web_ipkey(d.ip) ASC, d.mac LIMIT ");
    WT_EQ(web_query_compile(&q, 0, WEB_QS_IP, 10, 0, &s), 0);
    WT_HAS(s.sql, " ORDER BY web_ipkey(d.ip) IS NULL, web_ipkey(d.ip), d.ip, d.mac LIMIT ");
    WT_EQ(web_query_compile(&q, 0, WEB_SORT_PACK(WEB_QS_LAST, WEB_SORT_DESC), 10, 0, &s), 0);
    WT_HAS(s.sql, " ORDER BY d.last_seen IS NULL, d.last_seen DESC, d.mac LIMIT ");
    WT_EQ(web_query_compile(&q, 0, WEB_SORT_PACK(WEB_QS_MAC, WEB_SORT_DESC), 10, 0, &s), 0);
    WT_HAS(s.sql, " ORDER BY d.mac IS NULL, d.mac DESC LIMIT ");
    WT_EQ(web_query_compile(&q, 0, WEB_QS_LAST, 10, 0, &s), 0);
    WT_HAS(s.sql, " ORDER BY d.last_seen DESC, d.mac LIMIT ");
    WT_EQ(web_query_compile(&q, 0, WEB_QS_SIGNAL, 10, 0, &s), 0);
    WT_HAS(s.sql, " ORDER BY d.signal_dbm IS NULL, d.signal_dbm DESC, d.mac LIMIT ");
    static const char *const W[] = { "last", "first", "mac", "risk", "vendor", "ip",
                                     "ssid", "signal", "sources" };
    for (int i = 0; i < WEB_QS_COUNT; i++) WT_EQ(web_query_sort_find(W[i]), i);
    WT_EQ(web_query_sort_find("hostname"), -1);
    WT_EQ(web_query_sort_find("ip DESC"), -1);
    WT_EQ(web_sort_dir_find("asc"), WEB_SORT_ASC);
    WT_EQ(web_sort_dir_find("desc"), WEB_SORT_DESC);
    WT_EQ(web_sort_dir_find("ASC"), -1);
    WT_EQ(web_sort_dir_find("asc;"), -1);
    WT_EQ(web_sort_dir_find(""), -1);
}

/* The page: one table implementation, used by every table, its
 * headers interactive (not aria-hidden), its widths stored in a try,
 * a reset control, and each server-paged fetch carrying the header's
 * direction. Seen red with the ticker's DataTable() call removed. */
static void test_page_tables(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "  function DataTable(o) {");
    WT_HAS(p, "th.ariaSort = t.sortable(c) ? (on ? (t.dir > 0 ? \"ascending\" : \"descending\") : \"none\") : null;");
    WT_HAS(p, "      var v = JSON.parse(window.localStorage.getItem(DT_STORE + id) || \"null\");");
    WT_HAS(p, "    } catch (e) { /* no storage: the widths last until the page goes */ }");
    WT_HAS(p, "el(\"button\", \"dt-reset\", \"reset columns\")");
    WT_HAS(p, "rs.role = \"separator\";");
    WT_HAS(p, "rs.addEventListener(\"dblclick\"");
    WT_HAS(p, "if (e.key === \"ArrowLeft\") t.setWidth(c, t.px(c) - step);");
    static const char *const ID[] = {
        "id: \"devices\"", "id: \"aps\"", "id: \"flows\"", "id: \"hdevs\"",
        "id: \"halerts\"", "id: \"hflows\"", "id: \"alerts\"", "id: \"ticker\"",
        "id: \"sql\"", "id: \"anoms\"", "id: \"item.\" + title", "id: \"hnew.\" + k[0]",
        /* the Alerts page, an alert's page and the records view */
        "id: \"alertspage\"", "id: \"alertruns\"", "id: \"alertdev\"", "id: \"rectypes\"",
        "id: \"rectick\"",
    };
    for (size_t i = 0; i < sizeof(ID) / sizeof(ID[0]); i++) WT_HAS(p, ID[i]);
    static const char *const EL[] = {
        "id=\"d-head\"", "id=\"d-box\"", "id=\"w-aps-head\"", "id=\"w-aps-box\"",
        "id=\"f-head\"", "id=\"f-box\"", "id=\"h-devs-head\"", "id=\"h-alerts-head\"",
        "id=\"h-flows-head\"", "id=\"alerts-head\"", "id=\"ticker-head\"", "id=\"n-head\"",
        "id=\"n-mode\"", "id=\"d-rows\"", "id=\"w-aps\"", "id=\"f-rows\"", "id=\"h-devs\"",
        "id=\"h-alerts\"", "id=\"h-flows\"", "id=\"alerts\"", "id=\"ticker\"",
        "id=\"al-head\"", "id=\"al-box\"", "id=\"ad-history-head\"", "id=\"ad-history-box\"",
        "id=\"ad-dev-alerts-head\"", "id=\"ad-dev-alerts-box\"", "id=\"rc-head\"", "id=\"rc-box\"",
        "id=\"rc-thead\"", "id=\"rc-tbox\"",
    };
    for (size_t i = 0; i < sizeof(EL) / sizeof(EL[0]); i++) WT_HAS(p, EL[i]);
    WT_LACKS(p, "class=\"drow dhead\" aria-hidden");
    WT_LACKS(p, "class=\"aprow dhead\" aria-hidden");
    WT_LACKS(p, "class=\"alrow dhead\" aria-hidden");
    WT_LACKS(p, "class=\"rcrow dhead\" aria-hidden");
    /* The Overview's latest alerts are .alrow, a table's tracks: the
     * Alerts page's rows are a class of their own, no grid of theirs
     * laid over the Overview's (it was, before the two met). */
    WT_LACKS(p, ".alrow { display: grid;");
    WT_HAS(p, "if (dir === \"asc\" || dir === \"desc\") p += \"&dir=\" + dir;");
    WT_HAS(p, "getJSON(\"/api/wifi/aps?limit=100&sort=\" + encodeURIComponent(sort) + \"&dir=\" + wd.dir)");
    WT_HAS(p, "if (wd) p += \"&dir=\" + wd.dir;");
    WT_HAS(p, ".dt .dt-row { display: grid; grid-template-columns: var(--dt-cols);");
    /* The review's fixes, each pinned where it lives: a flex column the
     * user sized drawn at that size, its drag and arrows seeded from the
     * drawn width; a floor at the header's label; the separator's
     * maximum and text; body rows and cells in ARIA's table; a
     * server-paged prefix not sorted again; the SQL box's widths by
     * column name and its address and MAC columns typed; the list
     * tables' headers padded as their li rows. Each seen red with the
     * line removed. */
    WT_HAS(p, "tracks.push(c.flex && t.set(c) === null ? \"minmax(\" + px + \"px, 1fr)\" : px + \"px\");");
    WT_HAS(p, "var wd = Math.round(t.th[i].getBoundingClientRect().width);");
    WT_HAS(p, "var x0 = e.clientX, w0 = t.px(c);");
    WT_HAS(p, "return Math.max(Math.round((num(c.min) ? c.min : 4) * chPx()), t.labPx(c));");
    WT_HAS(p, "rs.ariaValueMax = \"4000\";");
    WT_HAS(p, "rs.ariaValueText = px + \" px\";");
    WT_HAS(p, "if (!row.children[k].role) row.children[k].role = \"cell\";");
    WT_HAS(p, "if (!p.role) p.role = \"rowgroup\";");
    WT_HAS(p, "}).observe(o.box, { childList: true, subtree: true });");
    WT_HAS(p, "if (!c || !t.dir || !c.val || (o.server && !complete)) return rows.slice();");
    WT_HAS(p, "D.rows = DTD.sort(rows.slice(0, DEV_MAX), !more && rows.length <= DEV_MAX);");
    WT_HAS(p, "DTF.sort(F.rows, !j.more)");
    WT_HAS(p, "DTA.sort(j.rows || [], !j.more)");
    WT_HAS(p, "return { k: \"n:\" + nm + (seen[nm] > 1 ? \"#\" + seen[nm] : \"\"), label: nm,");
    WT_HAS(p, "var type = allNum ? \"num\" : all(isIP) ? \"ip\"");
    WT_LACKS(p, "k: \"c\" + i");
    WT_HAS(p, ".dt > .dhead.alrow, .dt > .dhead.tkrow, .dt > .dhead.halrow, .dt > .dhead.hflrow { padding-left: 4px; padding-right: 4px; }");
}

#ifdef WITH_SQLITE

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

/* 1 when every needle is in b, in the order given. */
static int in_order(const char *b, const char *const *n, int k) {
    const char *at = b;
    for (int i = 0; i < k; i++) {
        const char *p = strstr(at, n[i]);
        if (!p) {
            fprintf(stderr, "    \"%s\" not after the previous\n", n[i]);
            return 0;
        }
        at = p + 1;
    }
    return 1;
}

static char g_dir[64];
static char g_db[128];
static web_rollup_t ru;
static web_tsdb_t ts;
static web_slothdb_t sdb;
static web_m4_t m4;
static web_health_t H;

static void db_up(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/slothweb-tables-XXXXXX");
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    char e2[64];
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, db_schema_version(), 0), 0);
    WT_EQ(sdb_exec(g_db,
        "INSERT INTO devices (mac,ip,vendor,last_ssid,signal_dbm,sources,is_ap,"
        "first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:01','10.0.0.10','Bvend','beta',-70,1,0,100,900),"
        " ('02:00:00:00:00:02','10.0.0.9','avend','Alpha',-40,3,0,200,800),"
        " ('02:00:00:00:00:03','9.0.0.200',NULL,NULL,NULL,7,0,300,700);"
        "INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,enc,akm,akm_bits,mfp,"
        "downgrade_flags,vendor,phy,has_wps,first_seen,last_seen) VALUES"
        " ('0a:00:00:00:00:01','zz',-80,36,'WPA2','PSK',4,0,0,NULL,'ac',0,10,900),"
        " ('0a:00:00:00:00:02','aa',-30,1,'WPA3','SAE',256,2,1,NULL,'ax',0,20,800),"
        " ('0a:00:00:00:00:03',NULL,NULL,11,'OPEN','',0,0,0,NULL,'n',0,30,700);"
        "INSERT INTO ssh_flows (src_ip,dst_ip,banner_count,server_banner,first_seen,"
        "last_seen) VALUES ('10.0.0.1','10.0.0.30',5,'x',1792620000,1792626000),"
        " ('10.0.0.2','10.0.0.20',9,'x',1792610000,1792625000),"
        " ('10.0.0.3','9.9.9.9',1,'x',1792615000,1792624000);"), 0);
    web_slothdb_init(&sdb, g_db, NULL);
    WT_EQ(web_rollup_init(&ru, 64, 0, e2, sizeof(e2)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, NULL, 30, 256, NULL, NULL), 0);
    memset(&m4, 0, sizeof(m4));
    m4.tsdb = &ts;
    m4.sdb = &sdb;
    m4.oui = web_oui_builtin();
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.tsdb = &ts;
    H.m4 = &m4;
}

static void db_down(void) {
    web_slothdb_destroy(&sdb);
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    const char *files[] = { "sloth.db", "sloth.db-wal", "sloth.db-shm" };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        char p[192];
        snprintf(p, sizeof(p), "%s/%s", g_dir, files[i]);
        unlink(p);
    }
    rmdir(g_dir);
}

/* /api/devices: each new word and both directions in the order sloth.db
 * gives (text by its bytes: "Bvend" before "avend"), an empty value last
 * either way; a refused dir is a 400 that never echoes it. Seen red
 * with the direction's empty key reversed (IS NOT NULL: the NULL
 * vendor first ascending), and with the bad_dir answer given the value
 * as its detail. */
static void test_devices_sorts(void) {
    db_up();
    static const char *const A1 = "\"02:00:00:00:00:01\"", *A2 = "\"02:00:00:00:00:02\"",
                             *A3 = "\"02:00:00:00:00:03\"";
    WT_EQ(route(&H, "/api/devices", "sort=vendor&dir=asc"), 200);
    const char *o1[] = { A1, A2, A3 };
    WT_ASSERT(in_order(body_of(g_out), o1, 3));
    WT_HAS(body_of(g_out), ",\"dir\":\"asc\"}");
    WT_EQ(route(&H, "/api/devices", "sort=vendor&dir=desc"), 200);
    const char *o2[] = { A2, A1, A3 };
    WT_ASSERT(in_order(body_of(g_out), o2, 3));
    WT_EQ(route(&H, "/api/devices", "sort=signal"), 200);
    WT_ASSERT(in_order(body_of(g_out), o2, 3));
    WT_LACKS(body_of(g_out), "\"dir\"");
    WT_EQ(route(&H, "/api/devices", "sort=signal&dir=asc"), 200);
    WT_ASSERT(in_order(body_of(g_out), o1, 3));
    WT_EQ(route(&H, "/api/devices", "sort=sources&dir=asc"), 200);
    WT_ASSERT(in_order(body_of(g_out), o1, 3));
    WT_EQ(route(&H, "/api/devices", "sort=first&dir=asc"), 200);
    WT_ASSERT(in_order(body_of(g_out), o1, 3));
    WT_EQ(route(&H, "/api/devices", "sort=ssid&dir=asc"), 200);
    WT_ASSERT(in_order(body_of(g_out), o2, 3));        /* "Alpha" before "beta" */
    /* Addresses by number, as the page compares them, not as text
     * (which puts 9.0.0.200 after 10.0.0.10). Seen red with the KEY
     * table's ip entry back at d.ip. */
    WT_EQ(route(&H, "/api/devices", "sort=ip&dir=desc"), 200);
    WT_ASSERT(in_order(body_of(g_out), (const char *[]){ A1, A2, A3 }, 3));
    WT_EQ(route(&H, "/api/devices", "sort=ip&dir=asc"), 200);
    WT_ASSERT(in_order(body_of(g_out), (const char *[]){ A3, A2, A1 }, 3));
    WT_EQ(route(&H, "/api/devices", "sort=ip"), 200);
    WT_ASSERT(in_order(body_of(g_out), (const char *[]){ A3, A2, A1 }, 3));
    WT_EQ(route(&H, "/api/devices", "dir=sideways"), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"bad_dir\"}");
    WT_LACKS(body_of(g_out), "sideways");
    WT_EQ(route(&H, "/api/devices", "sort=hostname"), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"bad_sort\"}");
    WT_EQ(route(&H, "/api/devices", "dir=asc&dir=desc"), 400);
    db_down();
}

/* /api/wifi/aps and /api/flows: the new words and directions; a
 * missing SSID last ascending and descending; refusals, never echoed
 * (seen red with each route's bad_dir given the value as its detail). */
static void test_aps_and_flows_sorts(void) {
    db_up();
    static const char *const B1 = "\"0a:00:00:00:00:01\"", *B2 = "\"0a:00:00:00:00:02\"",
                             *B3 = "\"0a:00:00:00:00:03\"";
    WT_EQ(route(&H, "/api/wifi/aps", "sort=ssid&dir=asc"), 200);
    WT_ASSERT(in_order(body_of(g_out), (const char *[]){ B2, B1, B3 }, 3));
    WT_HAS(body_of(g_out), ",\"dir\":\"asc\"}");
    WT_EQ(route(&H, "/api/wifi/aps", "sort=ssid&dir=desc"), 200);
    WT_ASSERT(in_order(body_of(g_out), (const char *[]){ B1, B2, B3 }, 3));
    WT_EQ(route(&H, "/api/wifi/aps", "sort=channel"), 200);
    WT_ASSERT(in_order(body_of(g_out), (const char *[]){ B2, B3, B1 }, 3));
    WT_EQ(route(&H, "/api/wifi/aps", "sort=signal&dir=asc"), 200);
    WT_ASSERT(in_order(body_of(g_out), (const char *[]){ B1, B2, B3 }, 3));
    WT_EQ(route(&H, "/api/wifi/aps", "sort=mfp&dir=desc"), 200);
    WT_ASSERT(in_order(body_of(g_out), (const char *[]){ B2, B1, B3 }, 3));
    WT_EQ(route(&H, "/api/wifi/aps", "sort=first&dir=asc"), 200);
    WT_ASSERT(in_order(body_of(g_out), (const char *[]){ B1, B2, B3 }, 3));
    WT_EQ(route(&H, "/api/wifi/aps", "sort=karma&dir=asc"), 200);
    WT_EQ(route(&H, "/api/wifi/aps", "sort=bssid&dir=desc"), 200);
    WT_ASSERT(in_order(body_of(g_out), (const char *[]){ B3, B2, B1 }, 3));
    WT_EQ(route(&H, "/api/wifi/aps", "sort=bssid&dir=up"), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"bad_dir\"}");
    WT_LACKS(body_of(g_out), "\"up\"");
    char q[200];
    snprintf(q, sizeof(q), "proto=ssh&from=%lld&to=%lld&sort=dst&dir=asc", T - 86400, T);
    WT_EQ(route(&H, "/api/flows", q), 200);
    const char *b = body_of(g_out);
    /* By number (9.9.9.9 first), not as text. Seen red with the
     * address columns ordered by their text. */
    WT_ASSERT(in_order(b, (const char *[]){ "\"9.9.9.9\"", "\"10.0.0.20\"", "\"10.0.0.30\"" }, 3));
    WT_HAS(b, ",\"dir\":\"asc\"}");
    snprintf(q, sizeof(q), "proto=ssh&from=%lld&to=%lld&sort=dst&dir=desc", T - 86400, T);
    WT_EQ(route(&H, "/api/flows", q), 200);
    WT_ASSERT(in_order(body_of(g_out), (const char *[]){ "\"10.0.0.30\"", "\"10.0.0.20\"",
                                                        "\"9.9.9.9\"" }, 3));
    snprintf(q, sizeof(q), "proto=ssh&from=%lld&to=%lld&sort=dst", T - 86400, T);
    WT_EQ(route(&H, "/api/flows", q), 200);
    WT_ASSERT(in_order(body_of(g_out), (const char *[]){ "\"9.9.9.9\"", "\"10.0.0.20\"",
                                                        "\"10.0.0.30\"" }, 3));
    snprintf(q, sizeof(q), "proto=ssh&from=%lld&to=%lld&sort=first", T - 86400, T);
    WT_EQ(route(&H, "/api/flows", q), 200);
    WT_ASSERT(in_order(body_of(g_out), (const char *[]){ "\"10.0.0.1\"", "\"10.0.0.3\"",
                                                        "\"10.0.0.2\"" }, 3));
    snprintf(q, sizeof(q), "proto=ssh&from=%lld&to=%lld&sort=total&dir=asc", T - 86400, T);
    WT_EQ(route(&H, "/api/flows", q), 200);
    WT_ASSERT(in_order(body_of(g_out), (const char *[]){ "\"10.0.0.3\"", "\"10.0.0.1\"",
                                                        "\"10.0.0.2\"" }, 3));
    snprintf(q, sizeof(q), "proto=ssh&from=%lld&to=%lld&dir=x1", T - 86400, T);
    WT_EQ(route(&H, "/api/flows", q), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"bad_dir\"}");
    WT_LACKS(body_of(g_out), "x1");
    db_down();
}

#endif

void run_tables_tests(void) {
    WT_RUN(test_dir_compiles_from_constants);
    WT_RUN(test_page_tables);
#ifdef WITH_SQLITE
    WT_RUN(test_devices_sorts);
    WT_RUN(test_aps_and_flows_sorts);
#endif
}
