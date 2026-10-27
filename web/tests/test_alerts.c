/* The Alerts page and the alert detail page (web_alerts.h) through the
 * route table, without a socket: a sloth.db generated from sloth's own
 * DDL (sdb_gen.c) on the pinned clock, and a live state fed lifecycle
 * records in the shape src/jsonl.c writes them. And the Overview's
 * tiles against the views they open, on the synthetic demo's own data
 * (web/tools/demo.c, linked in), and the bound the lists keep on a
 * large alerts table. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "sloth.h"
#include "web_alertdb.h"
#include "web_alertfmt.h"
#include "web_alertkb.h"
#include "web_alerts.h"
#include "web_anomaly.h"
#include "web_assets.h"
#include "web_ingest.h"
#include "web_live.h"
#include "web_routes.h"
#include "wtest.h"

#define T SDB_NOW
#define HR 3600LL
#define DY 86400LL

static char g_out[65536];

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static int route_m(const web_health_t *h, const char *path, const char *query, int head) {
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "%s", path);
    snprintf(rq.query, sizeof(rq.query), "%s", query);
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    rq.is_head = head;
    if (web_route(&rq, h, 1, g_out, sizeof(g_out), &r) != 0) return -1;
    g_out[r.out_len < sizeof(g_out) ? r.out_len : sizeof(g_out) - 1] = '\0';
    return r.status;
}

static int route(const web_health_t *h, const char *path, const char *query) {
    return route_m(h, path, query, 0);
}

/* The page carries the views and the links (spec: every tile a link). */
static void test_page_carries_the_alert_views(void) {
    const char *p = (const char *)web_page;
    static const char *const ids[] = {
        "v-alerts", "nav-alerts", "al-rows", "al-count", "al-sev", "al-type", "al-q",
        "al-state", "v-alert", "ad-what", "ad-why", "ad-fix", "ad-evidence",
        "ad-history", "ad-device", "ad-back", "v-records", "rc-rows", "v-health",
        "hl-rows", "t-tp", "t-devs", "t-alerts", "t-anoms", "t-rate", "t-sensor",
        "d-filter", "n-filter", "a-focus",
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        char want[64];
        snprintf(want, sizeof(want), "id=\"%s\"", ids[i]);
        if (!strstr(p, want)) fprintf(stderr, "    no %s\n", want);
        WT_HAS(p, want);
    }
    /* The tiles are links into the views they summarise. */
    WT_HAS(p, "href=\"#activity?focus=throughput\"");
    WT_HAS(p, "href=\"#devices?q=pass:latest\"");
    WT_HAS(p, "href=\"#alerts?state=open\"");
    WT_HAS(p, "href=\"#anomalies?state=open\"");
    WT_HAS(p, "href=\"#records\"");
    WT_HAS(p, "href=\"#health\"");
    /* The Alerts tab is no placeholder any more, and 6 opens it. */
    WT_LACKS(p, "not built: the Overview lists the latest alerts");
    WT_HAS(p, "if (e.key === \"6\") show(\"alerts\");");
    WT_HAS(p, "getJSON(\"/api/alert?id=\" + encodeURIComponent(id))");
    WT_HAS(p, "getJSON(\"/api/alerts?\" + alertsQuery(");
    /* No markup from data, ever. */
    WT_LACKS(p, "innerHTML");
    WT_LACKS(p, "insertAdjacentHTML");
    WT_LACKS(p, "document.write");
}

#ifndef WITH_SQLITE

void run_alerts_tests(void) {
    WT_RUN(test_page_carries_the_alert_views);
    /* Without SQLite the stream alone answers /api/alerts. */
    web_live_t *l = calloc(1, sizeof(*l));
    WT_ASSERT(l != NULL);
    if (!l) return;
    web_live_init(l, "unix:/t/s.sock");
    web_live_sock_connected(l, 0);
    web_feed_t f;
    memset(&f, 0, sizeof(f));         /* no metrics, no anomaly engine attached */
    web_feed_reset(&f);
    const char rec[] = "{\"type\":\"alert.create\",\"ts\":1,\"incident_id\":\"aaaa\","
                       "\"ty\":0,\"sev\":1,\"title\":\"PORT_SCAN\",\"key\":\"scan:x\"}\n";
    web_feed_bytes(&f, l, rec, strlen(rec), 1000);
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = 100;
    h.live = l;
    WT_EQ(route(&h, "/api/alerts", ""), 200);
    /* Named by slothweb's handle, never sloth's incident_id. */
    char want[64];
    snprintf(want, sizeof(want), "\"id\":\"s%s\",\"state\":\"open\"", l->inc[0].hid);
    WT_HAS(body_of(g_out), want);
    WT_LACKS(body_of(g_out), "aaaa");
    WT_HAS(body_of(g_out), "\"db\":\"none\"");
    WT_EQ(route(&h, "/api/alert", "id=d4"), 503);
    WT_HAS(body_of(g_out), "\"error\":\"no_sloth_db\"");
    web_live_destroy(l);
    free(l);
}

#else

#include <sqlite3.h>

/* The number after "name": in s, or -1. */
static long long num_of(const char *s, const char *name) {
    char k[64];
    snprintf(k, sizeof(k), "\"%s\":", name);
    const char *p = strstr(s, k);
    return p ? atoll(p + strlen(k)) : -1;
}

/* The list's own count, after its rows (a row has a "count" too). */
static long long rows_of(const char *s) {
    const char *p = strstr(s, "],\"count\":");
    return p ? atoll(p + 10) : -1;
}

static int count_of(const char *s, const char *needle) {
    int n = 0;
    for (const char *p = s; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

static char g_dir[64];
static char g_db[128];
static web_slothdb_t sdb;
static web_m4_t m4;
static web_health_t H;
static web_live_t *g_live;
static web_feed_t g_feed;

static void feed(const char *s) {
    web_feed_bytes(&g_feed, g_live, s, strlen(s), 1000);
}

/* sloth's incident_ids in the stream below: never on the wire. */
#define IA "a1f0c3e5d7b9a201"
#define IB "b2e4c6a8f0d1b302"
#define IC "c3d5e7f9a1b3c403"

/* The page's id of a stream incident ("s" and slothweb's handle), by
 * sloth's incident_id, as the route's test reads it off web_live_t;
 * a few buffers round, so three can be in one expression. */
static const char *S(const char *incident_id) {
    static char buf[4][WEB_LIVE_HID_MAX + 2];
    static int k;
    char *o = buf[k++ % 4];
    o[0] = '\0';
    for (int i = 0; i < g_live->ninc; i++)
        if (!strcmp(g_live->inc[i].id, incident_id))
            snprintf(o, WEB_LIVE_HID_MAX + 2, "s%s", g_live->inc[i].hid);
    for (int i = 0; !o[0] && i < g_live->closed_n; i++)
        if (!strcmp(g_live->closed[i].id, incident_id))
            snprintf(o, WEB_LIVE_HID_MAX + 2, "s%s", g_live->closed[i].hid);
    return o;
}

/* "id=" and S(incident_id), for a route's query. */
static const char *Q(const char *incident_id) {
    static char q[WEB_LIVE_HID_MAX + 8];
    snprintf(q, sizeof(q), "id=%s", S(incident_id));
    return q;
}

/* The rows, by rowid, so a test can name them:
 *   1-2   scan:192.0.2.50 three days ago, one run of two
 *   3-7   scan:192.0.2.50 today, one run of five (incidents 15 min
 *         apart): the key's 7 rows are one Alerts row, "incidents":7
 *   10    deauth:02:00:00:00:00:12@02:00:00:00:00:a1 (the stream has it
 *         too, closed): the MAC in the key is device ...:12
 *   11    smb1:192.0.2.18, match_ip 192.0.2.18: device ...:18 by address
 *   20-21 CLEARTEXT_CRED, the username in the key and the detail
 *   22    SNMP_COMMUNITY_BRUTE, the community in the detail
 *   30    scan:198.51.100.9, twenty days ago: out of the default window */
static const char CRED_KEY[] = "cred:10.0.0.1:10.0.0.9:21:FTP:alice-secret-user:0123456789abcdef";

static int seed(void) {
    char sql[8192];
    int n = snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,ip,hostname,vendor,first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:12','192.0.2.12','laptop',NULL,%lld,%lld),"
        " ('02:00:00:00:00:18','192.0.2.18','nas',NULL,%lld,%lld);"
        "INSERT INTO alerts (rowid,key,first_seen,last_seen,type,sev,title,detail,technique,"
        "match_ip,match_port,count) VALUES"
        " (1,'scan:192.0.2.50',%lld,%lld,0,1,'PORT_SCAN','192.0.2.50 scanned 9 distinct ports',"
        "'T1046','192.0.2.50',0,9),"
        " (2,'scan:192.0.2.50',%lld,%lld,0,1,'PORT_SCAN','192.0.2.50 scanned 9 distinct ports',"
        "'T1046','192.0.2.50',0,9),"
        " (3,'scan:192.0.2.50',%lld,%lld,0,0,'PORT_SCAN','192.0.2.50 scanned 8 distinct ports',"
        "'T1046','192.0.2.50',0,8),"
        " (4,'scan:192.0.2.50',%lld,%lld,0,1,'PORT_SCAN','192.0.2.50 scanned 8 distinct ports',"
        "'T1046','192.0.2.50',0,8),"
        " (5,'scan:192.0.2.50',%lld,%lld,0,1,'PORT_SCAN','192.0.2.50 scanned 8 distinct ports',"
        "'T1046','192.0.2.50',0,8),"
        " (6,'scan:192.0.2.50',%lld,%lld,0,1,'PORT_SCAN','192.0.2.50 scanned 8 distinct ports',"
        "'T1046','192.0.2.50',0,8),"
        " (7,'scan:192.0.2.50',%lld,%lld,0,1,'PORT_SCAN','192.0.2.50 scanned 12 distinct ports',"
        "'T1046','192.0.2.50',0,12),"
        " (10,'deauth:02:00:00:00:00:12@02:00:00:00:00:a1',%lld,%lld,1,2,'DEAUTH_FLOOD',"
        "'victim=02:00:00:00:00:12 bssid=02:00:00:00:00:a1 observed 40 frames','T1498.001',"
        "NULL,NULL,40),"
        " (11,'smb1:192.0.2.18',%lld,%lld,10,2,'SMB1_USE','SMBv1 traffic 192.0.2.20 -> "
        "192.0.2.18:445 (count=3).','T1210','192.0.2.18',445,3),"
        " (20,'%s',%lld,%lld,27,1,'CLEARTEXT_CRED','FTP user alice-secret-user in the clear on"
        " FTP -> 10.0.0.9:21','T1040','10.0.0.1',21,2),"
        " (21,'%s',%lld,%lld,27,1,'CLEARTEXT_CRED','FTP user alice-secret-user in the clear on"
        " FTP -> 10.0.0.9:21','T1040','10.0.0.1',21,1),"
        " (22,'snmp-brute:10.0.0.7->10.0.0.8',%lld,%lld,16,2,'SNMP_COMMUNITY_BRUTE',"
        "'10.0.0.7->10.0.0.8: 9 SNMP communities tried (last=community-secret-x)','T1110.001',"
        "'10.0.0.7',161,9),"
        " (30,'scan:198.51.100.9',%lld,%lld,0,0,'PORT_SCAN','198.51.100.9 scanned 8 distinct"
        " ports','T1046','198.51.100.9',0,8);",
        T - 10 * DY, T - 60, T - 10 * DY, T - 60,
        T - 3 * DY, T - 3 * DY + 300, T - 3 * DY + 1000, T - 3 * DY + 1300,
        T - 5 * HR, T - 5 * HR + 300, T - 5 * HR + 900, T - 5 * HR + 1200,
        T - 5 * HR + 1800, T - 5 * HR + 2100, T - 5 * HR + 2700, T - 5 * HR + 3000,
        T - 5 * HR + 3600, T - 5 * HR + 3900,
        T - 2 * HR, T - HR,
        T - 4 * HR, T - 1800,
        CRED_KEY, T - 2 * DY, T - 2 * DY + 60, CRED_KEY, T - HR, T - 30 * 60,
        T - 900, T - 600,
        T - 20 * DY, T - 20 * DY + 60);
    if (n < 0 || (size_t)n >= sizeof(sql)) return -1;
    return sdb_exec(g_db, sql);
}

/* The stream: a scan open (not in sloth.db), the deauth flood resolved
 * with a pcap (in sloth.db too), and a cleartext credential open, its
 * key and detail carrying the username. */
static void stream(void) {
    char b[4096];
    snprintf(b, sizeof(b),
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"a1f0c3e5d7b9a201\",\"key\":"
        "\"scan:192.0.2.77\",\"title\":\"PORT_SCAN\",\"detail\":\"192.0.2.77 scanned 12"
        " distinct ports\",\"sev\":1,\"ty\":0,\"count\":3,\"observations\":2,"
        "\"first_detected\":%lld,\"technique\":\"T1046\",\"match_ip\":\"192.0.2.77\","
        "\"match_port\":0}\n"
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"b2e4c6a8f0d1b302\",\"key\":"
        "\"deauth:02:00:00:00:00:12@02:00:00:00:00:a1\",\"title\":\"DEAUTH_FLOOD\","
        "\"detail\":\"victim=02:00:00:00:00:12 bssid=02:00:00:00:00:a1 observed 6 frames\","
        "\"sev\":1,\"ty\":1,\"count\":1}\n"
        "{\"type\":\"alert.escalate\",\"ts\":%lld,\"incident_id\":\"b2e4c6a8f0d1b302\",\"key\":"
        "\"deauth:02:00:00:00:00:12@02:00:00:00:00:a1\",\"title\":\"DEAUTH_FLOOD\","
        "\"detail\":\"victim=02:00:00:00:00:12 bssid=02:00:00:00:00:a1 observed 40 frames\","
        "\"sev\":2,\"prev_sev\":1,\"ty\":1,\"count\":5,"
        "\"pcap_path\":\"/var/lib/sloth/pcap/x.pcap\"}\n"
        "{\"type\":\"alert.resolve\",\"ts\":%lld,\"incident_id\":\"b2e4c6a8f0d1b302\",\"key\":"
        "\"deauth:02:00:00:00:00:12@02:00:00:00:00:a1\",\"title\":\"DEAUTH_FLOOD\","
        "\"sev\":2,\"ty\":1,\"count\":6,\"reason\":\"expired\"}\n"
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"c3d5e7f9a1b3c403\",\"key\":\"%s\","
        "\"title\":\"CLEARTEXT_CRED\",\"detail\":\"FTP user alice-secret-user in the clear on"
        " FTP -> 10.0.0.9:21\",\"sev\":1,\"ty\":27,\"count\":1,\"match_ip\":\"10.0.0.1\","
        "\"match_port\":21}\n",
        T - 600, T - 700, T - 3600, T - 3000, T - 120, T - 300, CRED_KEY);
    feed(b);
}

static void up(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/slothweb-alerts-XXXXXX");
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, db_schema_version(), 0), 0);
    WT_EQ(seed(), 0);
    g_live = calloc(1, sizeof(*g_live));
    WT_ASSERT(g_live != NULL);
    web_live_init(g_live, "unix:/test/sloth.sock");
    web_live_sock_connected(g_live, 0);
    web_feed_reset(&g_feed);
    stream();
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
    char p[192];
    snprintf(p, sizeof(p), "%s/sloth.db", g_dir);
    unlink(p);
    rmdir(g_dir);
}

/* Open first, then closed newest first; the scan key's seven rows are
 * one row with "incidents":7; a key the stream has is the stream's row
 * once, with sloth.db's count of its incidents. Seen red with
 * web_adb_groups() grouping by rid in place of key (every scan row
 * listed) and with the stream keys left out of f.exclude (deauth listed
 * twice). */
static void test_list_collapses_and_orders(void) {
    WT_EQ(route(&H, "/api/alerts", ""), 200);
    const char *b = body_of(g_out);
    WT_EQ(num_of(b, "open"), 2);
    WT_EQ(num_of(b, "open_all"), 2);
    /* The open two, sev then newest change: the credential, the scan. */
    char w1[96], w2[96], w3[96];
    snprintf(w1, sizeof(w1), "\"rows\":[{\"id\":\"%s\",\"state\":\"open\",\"source\":\"both\"", S(IC));
    snprintf(w2, sizeof(w2), ",{\"id\":\"%s\",\"state\":\"open\",\"source\":\"stream\"", S(IA));
    snprintf(w3, sizeof(w3), "{\"id\":\"%s\",\"state\":\"closed\",\"source\":\"both\"", S(IB));
    const char *r1 = strstr(b, w1);
    WT_ASSERT(r1 != NULL);
    const char *r2 = strstr(b, w2);
    WT_ASSERT(r2 != NULL && r2 > r1);
    /* Then the closed: the stream's deauth (sloth.db has its row), the
     * SNMP row, SMB1, the scan key once. */
    const char *r3 = strstr(b, w3);
    const char *r4 = strstr(b, "{\"id\":\"d22\",\"state\":\"recorded\",\"source\":\"sloth.db\"");
    const char *r5 = strstr(b, "{\"id\":\"d11\",\"state\":\"recorded\"");
    const char *r6 = strstr(b, "{\"id\":\"d7\",\"state\":\"recorded\"");
    WT_ASSERT(r3 && r4 && r5 && r6);
    WT_ASSERT(r2 < r3 && r3 < r4 && r4 < r5 && r5 < r6);
    WT_HAS(r6, "\"incidents\":7,\"reason\":null}");
    WT_HAS(r3, "\"incidents\":1,\"reason\":\"expired\"}");
    WT_HAS(r1, "\"incidents\":2,");
    WT_EQ(count_of(b, "\"type_name\":\"DEAUTH_FLOOD\""), 1);
    WT_EQ(count_of(b, "\"type_name\":\"PORT_SCAN\""), 2);
    WT_EQ(num_of(b, "total"), 6);
    WT_HAS(b, "\"more\":false,\"next_offset\":null");
    /* The out-of-window scan is there with a wider window. */
    WT_LACKS(b, "\"d30\"");
    WT_EQ(route(&H, "/api/alerts", "window=2592000"), 200);
    WT_HAS(body_of(g_out), "{\"id\":\"d30\",");
    /* The facets: groups per type. */
    WT_EQ(route(&H, "/api/alerts", ""), 200);
    WT_HAS(body_of(g_out), "{\"type\":0,\"name\":\"PORT_SCAN\",\"n\":2}");
}

static void test_filters_and_paging(void) {
    WT_EQ(route(&H, "/api/alerts", "state=open"), 200);
    WT_EQ(rows_of(body_of(g_out)), 2);
    WT_LACKS(body_of(g_out), "\"state\":\"recorded\"");
    WT_EQ(route(&H, "/api/alerts", "state=closed"), 200);
    WT_LACKS(body_of(g_out), "\"state\":\"open\"");
    WT_EQ(rows_of(body_of(g_out)), 4);
    WT_EQ(route(&H, "/api/alerts", "sev=crit"), 200);
    WT_EQ(rows_of(body_of(g_out)), 3);       /* deauth, smb1, snmp */
    WT_EQ(route(&H, "/api/alerts", "sev=low,warn&type=PORT_SCAN"), 200);
    WT_EQ(rows_of(body_of(g_out)), 2);       /* the stream's scan, d7 */
    WT_EQ(route(&H, "/api/alerts", "type=10"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[{\"id\":\"d11\"");
    WT_EQ(rows_of(body_of(g_out)), 1);
    WT_EQ(route(&H, "/api/alerts", "q=192.0.2.50"), 200);
    WT_EQ(rows_of(body_of(g_out)), 1);
    WT_EQ(route(&H, "/api/alerts", "q=smb1"), 200);  /* the type's name */
    WT_HAS(body_of(g_out), "\"rows\":[{\"id\":\"d11\"");
    WT_EQ(route(&H, "/api/alerts", "q=50%25"), 200); /* % is a character */
    WT_EQ(rows_of(body_of(g_out)), 0);
    /* Paging: one at a time, the next offset says where. */
    WT_EQ(route(&H, "/api/alerts", "limit=1&offset=2"), 200);
    char w4[64];
    snprintf(w4, sizeof(w4), "\"rows\":[{\"id\":\"%s\"", S(IB));
    WT_HAS(body_of(g_out), w4);
    WT_HAS(body_of(g_out), "\"more\":true,\"next_offset\":3");
    WT_EQ(route(&H, "/api/alerts", "limit=2&offset=5"), 200);
    WT_EQ(rows_of(body_of(g_out)), 1);
    /* Refusals, a word of slothweb's own, never the value. */
    static const char *const bad[][2] = {
        { "state=maybe", "bad_state" }, { "sev=crit,crit", "bad_sev" }, { "sev=high", "bad_sev" },
        { "sev=1,", "bad_sev" }, { "type=NOPE", "bad_type" }, { "type=90", "bad_type" },
        { "window=59", "bad_window" }, { "limit=0", "bad_limit" }, { "limit=101", "bad_limit" },
        { "offset=1001", "bad_offset" }, { "q=%01", "bad_value" }, { "id=d1", "unknown_parameter" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        WT_EQ(route(&H, "/api/alerts", bad[i][0]), 400);
        char want[64];
        snprintf(want, sizeof(want), "{\"error\":\"%s\"", bad[i][1]);
        WT_HAS(body_of(g_out), want);
    }
    WT_EQ(route_m(&H, "/api/alerts", "", 1), 405);
    WT_HAS(g_out, "Allow: GET\r\n");
    WT_EQ(route_m(&H, "/api/alert", "id=d7", 1), 405);
    static const char *const badid[] = { "", "id=", "id=x7", "id=d0", "id=d-1", "id=d1x",
                                         "id=s", "id=s<b>", "id=d99999999999999999999",
                                         "id=s012345678901234567890123456789012" };
    for (size_t i = 0; i < sizeof(badid) / sizeof(badid[0]); i++)
        WT_EQ(route(&H, "/api/alert", badid[i]), 400);
    WT_EQ(route(&H, "/api/alert", "id=d999"), 404);
    WT_HAS(body_of(g_out), "\"error\":\"no_such_alert\"");
    WT_EQ(route(&H, "/api/alert", "id=snope"), 404);
}

/* The detail page's sections for the collapsed scan key: what it is,
 * why it matters with its sources, how to fix it, the evidence, the
 * key's incidents as runs, and the device it names. Seen red with the
 * run gap test inverted (seven runs of one). */
static void test_detail_sections(void) {
    WT_EQ(route(&H, "/api/alert", "id=d4"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"id\":\"d4\",\"db\":\"open\",\"state\":\"recorded\",\"source\":\"sloth.db\"");
    WT_HAS(b, "\"db_id\":\"d7\"");
    WT_HAS(b, "\"type\":0,\"type_name\":\"PORT_SCAN\"");
    WT_HAS(b, "\"incidents\":7,");
    WT_EQ(num_of(b, "first_seen"), T - 3 * DY);
    /* The detail is audited for PORT_SCAN: shown, the row's own. */
    WT_HAS(b, "\"detail\":\"192.0.2.50 scanned 8 distinct ports\",\"detail_shown\":true");
    WT_HAS(b, "\"kb\":{\"name\":\"PORT_SCAN\",\"technique\":\"T1046\"");
    WT_HAS(b, "\"path\":\"research/mitre/T1595.md\"");
    WT_HAS(b, "\"investigate\":[\"");
    WT_HAS(b, "\"fix\":[\"");
    WT_HAS(b, "\"fix_sources\":[\"research/mitre/T1595.md\"]");
    /* Runs, newest first: the five today, the two three days ago. */
    char want[256];
    snprintf(want, sizeof(want), "\"runs\":[{\"from\":%lld,\"to\":%lld,\"incidents\":5,\"sev\":1,"
             "\"count\":44,\"id\":\"d7\"},{\"from\":%lld,\"to\":%lld,\"incidents\":2,\"sev\":1,"
             "\"count\":18,\"id\":\"d2\"}]", T - 5 * HR, T - 5 * HR + 3900, T - 3 * DY,
             T - 3 * DY + 1300);
    WT_HAS(b, want);
    WT_HAS(b, "\"device\":{\"mac\":null,\"ip\":\"192.0.2.50\"}");
    /* The device a key names by MAC, and one named by address. */
    WT_EQ(route(&H, "/api/alert", "id=d11"), 200);
    WT_HAS(body_of(g_out), "\"device\":{\"mac\":\"02:00:00:00:00:18\",\"ip\":\"192.0.2.18\"}");
    WT_EQ(route(&H, "/api/alert", "id=d10"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"device\":{\"mac\":\"02:00:00:00:00:12\",\"ip\":null}");
    /* The stream has this key: its live state comes with it. */
    char w5[128];
    snprintf(w5, sizeof(w5), "\"state\":\"closed\",\"source\":\"both\",\"stream_id\":\"%s\"", S(IB));
    WT_HAS(b, w5);
    WT_HAS(b, "\"pcap\":true");
}

/* A stream incident's evidence: the severity history, the pcap, the
 * reason. */
static void test_stream_detail(void) {
    WT_EQ(route(&H, "/api/alert", Q(IB)), 200);
    const char *b = body_of(g_out);
    char want[256];
    snprintf(want, sizeof(want), "\"sev_history\":[{\"ts\":%lld,\"sev\":1,\"ev\":\"create\"},"
             "{\"ts\":%lld,\"sev\":2,\"ev\":\"escalate\"},{\"ts\":%lld,\"sev\":2,\"ev\":\"resolve\"}]",
             T - 3600, T - 3000, T - 120);
    WT_HAS(b, want);
    WT_HAS(b, "\"reason\":\"expired\",\"pcap\":true");
    WT_HAS(b, "\"db_id\":\"d10\"");
    WT_HAS(b, "\"incidents\":1,");
    WT_EQ(route(&H, "/api/alert", Q(IA)), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"state\":\"open\",\"source\":\"stream\"");
    WT_HAS(b, "\"pcap\":false");
    WT_HAS(b, "\"detail\":\"192.0.2.77 scanned 12 distinct ports\"");
    WT_HAS(b, "\"runs\":[]");
}

/* Neither the key (alerts.key, or the stream's key) nor the detail of a
 * credential-bearing type reaches any body, by any route. The username
 * and the community are in both sources' keys and details here.
 * Each absence seen red by a one-line mutant, restored by the inverse
 * edit: web_alert_detail_ok() answering 1 (the username in /api/alert
 * and /api/live, the community in /api/alert); e->key written into
 * row_json() (the username, "cred:" and "key" in /api/alerts); the
 * ticker summary's gate removed (the username in the ring); sloth.db's
 * detail selected without web_detail_ok() (has_detail 1); the
 * typed-detail column opened by pred_ok (SELECT detail prepared); the
 * stream's detail kept for every type (the incident's detail set). */
static void test_key_and_withheld_detail_never_served(void) {
    static const struct { const char *path, *query; } R[] = {
        { "/api/alerts", "" }, { "/api/alerts", "state=open" }, { "/api/alerts", "q=alice" },
        { "/api/alerts", "type=CLEARTEXT_CRED" }, { "/api/alerts", "window=34560000" },
        { "/api/alert", NULL }, { "/api/alert", "id=d20" }, { "/api/alert", "id=d21" },
        { "/api/alert", "id=d22" }, { "/api/history/alerts", "" },
        { "/api/device/02:00:00:00:00:12", "" }, { "/api/live", "" },
    };
    for (size_t i = 0; i < sizeof(R) / sizeof(R[0]); i++) {
        const char *q = R[i].query ? R[i].query : Q(IC);   /* the credential's page */
        int st = route(&H, R[i].path, q);
        if (st != 200) fprintf(stderr, "    %s?%s: %d\n", R[i].path, q, st);
        WT_EQ(st, 200);
        const char *b = body_of(g_out);
        if (strstr(b, "alice") || strstr(b, "community-secret") || strstr(b, "cred:"))
            fprintf(stderr, "    %s?%s carries it\n", R[i].path, q);
        WT_LACKS(b, "alice");
        WT_LACKS(b, "community-secret");
        WT_LACKS(b, "cred:");
        WT_LACKS(b, "snmp-brute:");
        WT_LACKS(b, "\"key\":");
    }
    /* Withheld, and said to be. */
    WT_EQ(route(&H, "/api/alert", "id=d22"), 200);
    WT_HAS(body_of(g_out), "\"detail\":null,\"detail_shown\":false");
    WT_EQ(route(&H, "/api/alert", Q(IC)), 200);
    WT_HAS(body_of(g_out), "\"detail\":null,\"detail_shown\":false");
    WT_HAS(body_of(g_out), "\"incidents\":2,");
    /* The ticker's summary of the credential record: the title alone. */
    web_live_rec_t out[WEB_LIVE_RING];
    unsigned long long latest;
    int n = web_live_recent_after(g_live, 0, out, WEB_LIVE_RING, &latest);
    WT_ASSERT(n >= 5);
    for (int i = 0; i < n; i++) WT_ASSERT(!strstr(out[i].text, "alice"));
    /* The stream's incident does not even keep it (the route's own gate
     * would hide it too, so this is the one place the first is seen). */
    web_live_inc_t *inc = calloc(1, sizeof(*inc));
    WT_ASSERT(inc != NULL);
    if (inc) {
        WT_EQ(web_live_incident(g_live, S(IC) + 1, inc), 1);
        WT_EQ(inc->detail[0], '\0');
        WT_EQ(web_live_incident(g_live, S(IA) + 1, inc), 1);
        WT_HAS(inc->detail, "192.0.2.77 scanned 12 distinct ports");
        free(inc);
    }
    /* And the reader's own row: the detail stays inside SQLite. */
    web_sdb_conn_t c;
    char err[WEB_SDB_ERR_MAX];
    WT_EQ(web_slothdb_open(&sdb, &c, 500, T, err, sizeof(err)), 0);
    web_adb_row_t r;
    WT_EQ(web_adb_row(&c, 20, &r), 1);
    WT_EQ(r.has_detail, 0);
    WT_LACKS(r.detail, "alice");
    WT_EQ(web_adb_row(&c, 7, &r), 1);
    WT_EQ(r.has_detail, 1);
    /* detail is typed-detail: no other statement can name it. */
    sqlite3_stmt *st = NULL;
    c.pred_ok = 1;
    WT_ASSERT(sqlite3_prepare_v2(c.db, "SELECT detail FROM alerts", -1, &st, NULL) != SQLITE_OK);
    sqlite3_finalize(st);
    c.pred_ok = 0;
    c.detail_ok = 1;
    WT_ASSERT(sqlite3_prepare_v2(c.db, "SELECT key FROM alerts", -1, &st, NULL) != SQLITE_OK);
    sqlite3_finalize(st);
    c.detail_ok = 0;
    web_slothdb_close(&c);
}

/* sloth's incident_id inverts to the unsalted hash of the alert's key
 * (web_live.h), so no body carries one: every incident is named by
 * slothweb's handle. Seen red by two one-line mutants, each restored by
 * the inverse edit: row_json() writing e->id for e->hid (/api/alerts
 * and the list's links), and /api/live writing the incident_id again in
 * place of the handle. */
static void test_incident_ids_never_served(void) {
    static const char *const ids[] = { IA, IB, IC };
    const char *qs[][2] = {
        { "/api/alerts", "" }, { "/api/alerts", "state=open" }, { "/api/alerts", "state=closed" },
        { "/api/alerts", "window=34560000" }, { "/api/alert", "id=d10" },
        { "/api/alert", "id=d20" }, { "/api/history/alerts", "" },
        { "/api/device/02:00:00:00:00:12", "" }, { "/api/live", "" },
        { "/api/alert", NULL }, { "/api/alert", NULL }, { "/api/alert", NULL },
    };
    char qa[3][WEB_LIVE_HID_MAX + 8];
    for (int k = 0; k < 3; k++) {
        snprintf(qa[k], sizeof(qa[k]), "%s", Q(ids[k]));
        WT_ASSERT(strlen(qa[k]) > 4);
        qs[9 + k][1] = qa[k];
    }
    for (size_t i = 0; i < sizeof(qs) / sizeof(qs[0]); i++) {
        WT_EQ(route(&H, qs[i][0], qs[i][1]), 200);
        const char *b = body_of(g_out);
        for (int k = 0; k < 3; k++) {
            if (strstr(b, ids[k])) fprintf(stderr, "    %s?%s carries %s\n", qs[i][0], qs[i][1], ids[k]);
            WT_LACKS(b, ids[k]);
        }
        WT_LACKS(b, "incident_id");
    }
    /* The handles are what the list links by. */
    WT_EQ(route(&H, "/api/alerts", ""), 200);
    for (int k = 0; k < 3; k++) {
        char want[64];
        snprintf(want, sizeof(want), "{\"id\":\"%s\",", S(ids[k]));
        WT_HAS(body_of(g_out), want);
    }
}

/* One row per key in the stream too: a key opened and resolved twice,
 * then open a third time, is one row (its open incident) with every
 * incident counted, and a key only closed twice is one closed row, the
 * newest of the two. Seen red with the key test in row_of_key()
 * answering -1 (three rows, then two). */
static void test_stream_groups_by_key(void) {
    web_live_t *l = calloc(1, sizeof(*l));
    WT_ASSERT(l != NULL);
    if (!l) return;
    web_live_init(l, "unix:/t/s.sock");
    web_live_sock_connected(l, 0);
    web_feed_t f;
    memset(&f, 0, sizeof(f));
    web_feed_reset(&f);
    char b[4096];
    size_t o = 0;
    static const char *const life[] = { "create", "resolve" };
    for (int cyc = 0; cyc < 2; cyc++)
        for (int k = 0; k < 2; k++)
            for (int e = 0; e < 2; e++)
                o += (size_t)snprintf(b + o, sizeof(b) - o,
                    "{\"type\":\"alert.%s\",\"ts\":%lld,\"incident_id\":\"9%d%d0\","
                    "\"key\":\"scan:192.0.2.%d\",\"title\":\"PORT_SCAN\",\"sev\":1,\"ty\":0,"
                    "\"count\":%d,\"first_detected\":%lld,\"reopen_count\":%d}\n",
                    life[e], T - 3000 + cyc * 1000 + k * 10 + e * 100, cyc, k, 60 + k,
                    2 + cyc, T - 3000 + cyc * 1000 + k * 10, cyc);
    o += (size_t)snprintf(b + o, sizeof(b) - o,
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"9200\","
        "\"key\":\"scan:192.0.2.60\",\"title\":\"PORT_SCAN\",\"sev\":2,\"ty\":0,"
        "\"count\":4,\"first_detected\":%lld,\"reopen_count\":2}\n", T - 100, T - 100);
    web_feed_bytes(&f, l, b, o, 1000);
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T;
    h.live = l;
    WT_EQ(route(&h, "/api/alerts", ""), 200);
    const char *body = body_of(g_out);
    WT_EQ(rows_of(body), 2);
    WT_EQ(num_of(body, "open"), 1);
    WT_EQ(count_of(body, "\"ip\":null"), 2);
    /* .60: its open incident, three incidents, counts summed, the
     * first incident's start. */
    char want[256];
    snprintf(want, sizeof(want), "\"state\":\"open\",\"source\":\"stream\",\"type\":0,"
             "\"type_name\":\"PORT_SCAN\",\"title\":\"PORT_SCAN\",\"sev\":2,");
    WT_HAS(body, want);
    snprintf(want, sizeof(want), "\"first_seen\":%lld,\"last_seen\":%lld,\"count\":9,"
             "\"incidents\":3,", T - 3000, T - 100);
    WT_HAS(body, want);
    /* .61: closed twice, the newer shown, both counted. */
    snprintf(want, sizeof(want), "\"state\":\"closed\",\"source\":\"stream\"");
    WT_HAS(body, want);
    snprintf(want, sizeof(want), "\"first_seen\":%lld,\"last_seen\":%lld,\"count\":5,"
             "\"incidents\":2,", T - 2990, T - 1890);
    WT_HAS(body, want);
    /* The facets count a key once. */
    WT_HAS(body, "{\"type\":0,\"name\":\"PORT_SCAN\",\"n\":2}");
    /* state=closed: the closed incidents of .60 are its row there. */
    WT_EQ(route(&h, "/api/alerts", "state=closed"), 200);
    WT_EQ(rows_of(body_of(g_out)), 2);
    web_live_destroy(l);
    free(l);
}

/* History's alerts in the range and the drawer's alerts naming a
 * device, collapsed the same way, each with the detail page's id.
 * Seen red with the History statement grouping by rid in place of key. */
static void test_history_and_drawer_collapse(void) {
    char q[96];
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - 7 * DY, T);
    WT_EQ(route(&H, "/api/history/alerts", q), 200);
    const char *b = body_of(g_out);
    WT_EQ(count_of(b, "\"title\":\"PORT_SCAN\""), 1);
    WT_HAS(b, "\"incidents\":7,\"id\":\"d7\"}");
    WT_EQ(route(&H, "/api/device/02:00:00:00:00:12", ""), 200);
    WT_HAS(body_of(g_out), "\"title\":\"DEAUTH_FLOOD\",\"type\":1,\"sev\":2,\"count\":40,"
                           "\"incidents\":1,\"id\":\"d10\"");
}

/* Every type renders its detail page, kb included, within the
 * connection's buffer, the largest with a full page of runs. */
static void test_every_type_renders(void) {
    char sql[512];
    size_t big = 0;
    int bigt = 0;
    for (int t = 0; t < web_akb_n; t++) {
        snprintf(sql, sizeof(sql), "INSERT INTO alerts (rowid,key,first_seen,last_seen,type,"
                 "sev,title,detail,count) VALUES (%d,'kb:%d',%lld,%lld,%d,1,'T','d',1)",
                 1000 + t, t, T - 3 * DY, T - 3 * DY + 10, t);
        WT_EQ(sdb_exec(g_db, sql), 0);
        char id[32];
        snprintf(id, sizeof(id), "id=d%d", 1000 + t);
        WT_EQ(route(&H, "/api/alert", id), 200);
        char want[96];
        snprintf(want, sizeof(want), "\"kb\":{\"name\":\"%s\"", web_akb[t].name);
        WT_HAS(body_of(g_out), want);
        size_t n = strlen(body_of(g_out));
        if (n > big) { big = n; bigt = t; }
    }
    /* The largest, with 300 incidents an hour apart: 100 runs, more. */
    for (int i = 0; i < 300; i++) {
        snprintf(sql, sizeof(sql), "INSERT INTO alerts (key,first_seen,last_seen,type,sev,"
                 "title,detail,count) VALUES ('kb:%d',%lld,%lld,%d,1,'T','d',1)", bigt,
                 T - 4 * DY - (long long)i * HR, T - 4 * DY - (long long)i * HR + 10, bigt);
        WT_EQ(sdb_exec(g_db, sql), 0);
    }
    char id[32];
    snprintf(id, sizeof(id), "id=d%d", 1000 + bigt);
    WT_EQ(route(&H, "/api/alert", id), 200);
    WT_EQ(count_of(body_of(g_out), "\"from\":"), WEB_ALERT_RUNS);
    WT_HAS(body_of(g_out), "],\"more\":true}}");
    snprintf(sql, sizeof(sql), "DELETE FROM alerts WHERE key LIKE 'kb:%%'");
    WT_EQ(sdb_exec(g_db, sql), 0);
}

static double ms_since(const struct timespec *a) {
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    return (double)(b.tv_sec - a->tv_sec) * 1e3 + (double)(b.tv_nsec - a->tv_nsec) / 1e6;
}

/* rows alerts rows on keys of about per rows each (sloth's churn on the
 * owner's host, #170, is about 114), spread over 30 days, written in one
 * transaction by a recursive CTE. */
static int fill(const char *db, long long rows, long long per) {
    char sql[1024];
    snprintf(sql, sizeof(sql),
        "BEGIN; WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i < %lld)"
        " INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,match_ip,count)"
        " SELECT 'big:' || (i / %lld) || ':10.1.' || ((i / %lld) %% 250) || '.9',"
        " %lld - (i * 2592000 / %lld), %lld - (i * 2592000 / %lld) + 60, (i / %lld) %% 90,"
        " i %% 3, 'BIG', '10.1.0.9 scanned 9 distinct ports', '10.1.0.9', 1 FROM n; COMMIT;",
        rows - 1, per, per, T, rows, T, rows, per);
    return sdb_exec(db, sql);
}

/* The lists read at most WEB_ADB_SCAN_CAP rows, newest first, and say
 * so; on a table of 30,000 the answer stays inside the request budget.
 * With SLOTHWEB_ALERTS_BENCH set, the same on 500,000 rows, timed
 * (web/README.md quotes the figures). Seen red with the window's LIMIT
 * made -1 (more rows read than the bound, and a 503 past the budget). */
static void test_lists_stay_bounded(void) {
    const char *bench = getenv("SLOTHWEB_ALERTS_BENCH");
    long long rows = bench ? 500000 : 30000;
    char p[160];
    snprintf(p, sizeof(p), "%s/big.db", g_dir);
    WT_EQ(sdb_make(p, db_schema_version(), 0), 0);
    WT_EQ(fill(p, rows, 114), 0);
    web_slothdb_t s2;
    web_slothdb_init(&s2, p, NULL);
    web_m4_t m2;
    memset(&m2, 0, sizeof(m2));
    m2.sdb = &s2;
    web_health_t h2 = H;
    h2.m4 = &m2;
    h2.live = NULL;
    static const char *const qs[] = { "", "window=2592000", "sev=crit", "type=5", "q=10.1.3",
                                      "limit=100&offset=900", "state=closed&q=BIG" };
    for (size_t i = 0; i < sizeof(qs) / sizeof(qs[0]); i++) {
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int st = route(&h2, "/api/alerts", qs[i]);
        double ms = ms_since(&t0);
        WT_EQ(st, 200);
        const char *b = body_of(g_out);
        if (bench) fprintf(stderr, "    %lld rows, /api/alerts?%s: %.1f ms, scan %lld\n", rows,
                           qs[i], ms, strstr(b, "\"scan\":") ? num_of(strstr(b, "\"scan\":"), "rows") : -1);
        WT_ASSERT(num_of(strstr(b, "\"scan\":") ? strstr(b, "\"scan\":") : b, "rows") <=
                  WEB_ADB_SCAN_CAP);
        WT_ASSERT(ms < 2000);
    }
    WT_EQ(route(&h2, "/api/alerts", "window=2592000"), 200);
    const char *sc = strstr(body_of(g_out), "\"scan\":");
    WT_ASSERT(sc != NULL);
    if (sc) {
        WT_EQ(num_of(sc, "rows"), WEB_ADB_SCAN_CAP);
        WT_HAS(sc, "\"capped\":true");
    }
    /* One key's page and its history: through the key's index. */
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    WT_EQ(route(&h2, "/api/alert", "id=d1"), 200);
    double ms = ms_since(&t0);
    if (bench) fprintf(stderr, "    %lld rows, /api/alert?id=d1: %.1f ms\n", rows, ms);
    WT_HAS(body_of(g_out), "\"incidents\":114,");
    char q[96];
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - 30 * DY, T);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    WT_EQ(route(&h2, "/api/history/alerts", q), 200);
    ms = ms_since(&t0);
    if (bench) fprintf(stderr, "    %lld rows, /api/history/alerts 30 d: %.1f ms\n", rows, ms);
    WT_EQ(route(&h2, "/api/device/02:00:00:00:00:01", ""), 200);
    web_slothdb_destroy(&s2);
    unlink(p);
}

/* Past the cap, the filters still reach: the predicates are inside the
 * bounded read, so an old row of a rare type, title or address is found
 * by asking for it, and the facets name its type. History counts a
 * listed key over every row of it in the range, not the rows that fell
 * inside the scan, and says the scan was capped and how far back it
 * went; the drawer finds a device's alert older than the newest
 * WEB_SDB_ALERT_SCAN rows of every device. Each was seen red on the
 * parent's statements (the cap applied before the filter, and a global
 * newest-rows read under the drawer's). */
static void test_filters_reach_past_the_cap(void) {
    char p[160];
    snprintf(p, sizeof(p), "%s/cap.db", g_dir);
    WT_EQ(sdb_make(p, db_schema_version(), 0), 0);
    WT_EQ(fill(p, 30000, 114), 0);
    char sql[1024];
    snprintf(sql, sizeof(sql),
        "INSERT INTO alerts (rowid,key,first_seen,last_seen,type,sev,title,detail,match_ip,count)"
        " VALUES (900001,'rare:203.0.113.77',%lld,%lld,88,2,'RAREOLD','x','203.0.113.77',3),"
        " (900002,'span:203.0.113.78',%lld,%lld,5,1,'SPANKEY','x','203.0.113.78',4),"
        " (900003,'span:203.0.113.78',%lld,%lld,5,1,'SPANKEY','x','203.0.113.78',6),"
        " (900004,'deauth:02:00:00:00:00:99@02:00:00:00:00:a9',%lld,%lld,1,2,'OLDDEAUTH','x',"
        "NULL,7);"
        "INSERT INTO devices (mac,ip,hostname,vendor,first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:99','192.0.2.99','old',NULL,%lld,%lld);",
        T - 29 * DY, T - 29 * DY + 60, T - 29 * DY, T - 29 * DY + 60, T - 120, T - 60,
        T - 28 * DY, T - 28 * DY + 60, T - 29 * DY, T - 60);
    WT_EQ(sdb_exec(p, sql), 0);
    web_slothdb_t s2;
    web_slothdb_init(&s2, p, NULL);
    web_m4_t m2;
    memset(&m2, 0, sizeof(m2));
    m2.sdb = &s2;
    web_health_t h2 = H;
    h2.m4 = &m2;
    h2.live = NULL;
    /* The wide window is capped, and says how far back it reached. */
    WT_EQ(route(&h2, "/api/alerts", "window=2592000"), 200);
    const char *sc = strstr(body_of(g_out), "\"scan\":");
    WT_ASSERT(sc != NULL);
    if (sc) {
        WT_HAS(sc, "\"capped\":true");
        long long oldest = num_of(sc, "oldest");
        WT_ASSERT(oldest > T - 21 * DY && oldest < T - 19 * DY);
    }
    WT_LACKS(body_of(g_out), "RAREOLD");
    static const char *const qs[] = { "window=2592000&type=88", "window=2592000&q=RAREOLD",
                                      "window=2592000&q=203.0.113.77",
                                      "window=2592000&sev=crit&q=rare" };
    for (size_t i = 0; i < sizeof(qs) / sizeof(qs[0]); i++) {
        WT_EQ(route(&h2, "/api/alerts", qs[i]), 200);
        if (!strstr(body_of(g_out), "\"id\":\"d900001\""))
            fprintf(stderr, "    /api/alerts?%s misses the old row\n", qs[i]);
        WT_HAS(body_of(g_out), "\"id\":\"d900001\"");
    }
    WT_EQ(route(&h2, "/api/alerts", "window=2592000&q=RAREOLD"), 200);
    WT_HAS(body_of(g_out), "\"scan\":{\"rows\":1,");
    WT_HAS(body_of(g_out), "{\"type\":88,\"name\":");
    /* History over 30 days: capped, and SPANKEY's two rows both counted
     * though the older lies past the scan. */
    char q[96];
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - 30 * DY, T);
    WT_EQ(route(&h2, "/api/history/alerts", q), 200);
    const char *b = body_of(g_out);
    char want[192];
    snprintf(want, sizeof(want), "{\"title\":\"SPANKEY\",\"ip\":\"203.0.113.78\",\"type\":5,"
             "\"sev\":1,\"count\":10,\"first_seen\":%lld,\"last_seen\":%lld,\"incidents\":2,",
             T - 29 * DY, T - 60);
    WT_HAS(b, want);
    WT_HAS(b, "\"scan\":{\"rows\":20000,\"cap\":20000,\"capped\":true,\"oldest\":");
    /* The drawer: the device's month-old alert. */
    WT_EQ(route(&h2, "/api/device/02:00:00:00:00:99", ""), 200);
    WT_HAS(body_of(g_out), "\"title\":\"OLDDEAUTH\"");
    web_slothdb_destroy(&s2);
    unlink(p);
}

/* ── the Overview's tiles, on the demo's data ────────────────────────── */

int    demo_make_db(const char *path, long long now);
size_t demo_pass(long long t, long long start, unsigned long k, char *out, size_t cap);

/* Each tile's number is the row count of the view it opens: devices
 * (the latest pass) and the Devices view's pass:latest; open alerts and
 * the Alerts page's state=open; open anomalies and /api/anomalies' open
 * episodes; records/s and the Records view's per-type rates, summed.
 * Throughput and sensor health are a rate and a word, not counts: their
 * views show the same series and the same word, which the page reads
 * from the same members. Seen red with web_inpass() answering 1 for
 * every MAC (24 devices for a pass of 23). */
static void test_tiles_equal_their_views_on_demo_data(void) {
    char p[160];
    snprintf(p, sizeof(p), "%s/demo.db", g_dir);
    WT_EQ(demo_make_db(p, T), 0);
    web_live_t *l = calloc(1, sizeof(*l));
    WT_ASSERT(l != NULL);
    if (!l) return;
    web_live_init(l, "unix:/demo/sloth.sock");
    web_live_sock_connected(l, 0);
    web_feed_t f;
    memset(&f, 0, sizeof(f));         /* no metrics, no anomaly engine attached */
    web_feed_reset(&f);
    static char buf[1 << 16];
    /* 700 passes a second apart: a scan opened and closed fifteen times,
     * SMB1 escalated, the deauth flood's burst, the two left open. */
    long long start = T - 700, now_ms = 0;
    for (unsigned long k = 0; k < 700; k++) {
        size_t n = demo_pass(start + (long long)k, start, k, buf, sizeof(buf));
        now_ms = (long long)k * 1000 + 500;
        web_feed_bytes(&f, l, buf, n, now_ms);
    }
    web_sdb_fns_t fns = { NULL, NULL, NULL, l };
    web_slothdb_t s3;
    web_slothdb_init(&s3, p, &fns);
    web_m4_t m3;
    memset(&m3, 0, sizeof(m3));
    m3.sdb = &s3;
    web_anomaly_t an;
    web_anom_cfg_t acfg;
    memset(&acfg, 0, sizeof(acfg));
    WT_EQ(web_anomaly_init(&an, 64, &acfg), 0);
    web_store_ep_t e[5];
    memset(e, 0, sizeof(e));
    for (int i = 0; i < 5; i++) {
        e[i].id = 10 + i;
        snprintf(e[i].kind, sizeof(e[i].kind), "A6");
        e[i].metric = -1;
        snprintf(e[i].key, sizeof(e[i].key), "192.0.2.%d", 10 + i);
        e[i].state = i < 3 ? WEB_EP_OPEN : WEB_EP_CLOSED;
        e[i].score = e[i].peak = 40;
        e[i].first_seen = e[i].last_seen = e[i].last_bucket = T - 60;
        web_anomaly_restore_episode(&an, &e[i]);
    }
    m3.anomaly = &an;
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T;
    h.m4 = &m3;
    h.live = l;
    h.anomaly = &an;
    h.now_ms = now_ms;
    web_live_sum_t s;
    web_live_summary(l, &s, now_ms);

    /* devices */
    WT_ASSERT(s.dev_known);
    WT_EQ(route(&h, "/api/devices", "q=pass:latest&limit=200"), 200);
    WT_EQ(count_of(body_of(g_out), "{\"mac\":"), s.devices);
    WT_EQ(s.devices, 23);
    /* open alerts */
    long long open = (long long)(s.alerts[0] + s.alerts[1] + s.alerts[2]);
    WT_EQ(route(&h, "/api/alerts", "state=open&limit=100"), 200);
    WT_EQ(rows_of(body_of(g_out)), open);
    WT_EQ(count_of(body_of(g_out), "\"state\":\"open\""), open);
    WT_ASSERT(open >= 2);
    /* open anomalies */
    WT_EQ(route(&h, "/api/anomalies", ""), 200);
    WT_EQ(count_of(body_of(g_out), "\"open\":true"), web_anomaly_open_count(&an));
    WT_EQ(web_anomaly_open_count(&an), 3);
    /* records/s: the per-type rates sum to the tile's */
    static char lj[65536];
    WT_ASSERT(web_live_json(l, lj, sizeof(lj), now_ms) > 0);
    const char *tr = strstr(lj, "\"types_rate\":{");
    WT_ASSERT(tr != NULL);
    long sum10 = 0;
    for (const char *q = tr ? tr + 14 : ""; *q && *q != '}'; ) {
        const char *c = strchr(q, ':');
        if (!c) break;
        double v = atof(c + 1);
        sum10 += (long)(v * 10 + 0.5);
        q = c + 1;
        while (*q && *q != ',' && *q != '}') q++;
        if (*q == ',') q++;
    }
    sum10 += (long)(atof(strstr(lj, "\"types_other_rate\":") + 19) * 10 + 0.5);
    sum10 += (long)(atof(strstr(lj, "\"types_invalid_rate\":") + 21) * 10 + 0.5);
    WT_EQ(sum10, s.rate10);
    WT_ASSERT(s.rate10 > 0);
    /* The demo's credential: its username nowhere. */
    WT_EQ(route(&h, "/api/alerts", ""), 200);
    WT_LACKS(body_of(g_out), "demo-user");
    WT_HAS(body_of(g_out), "\"type_name\":\"KARMA_AP\"");
    web_anomaly_destroy(&an);
    web_slothdb_destroy(&s3);
    web_live_destroy(l);
    free(l);
    unlink(p);
}

/* sloth writes an SSID into an alert's title and detail as it came
 * (src/alerts/rules_twin.c): every route sends both in the display
 * form (web_ssid.h), the stream's (kept so by web_live.c) and
 * sloth.db's (escaped as they are written) alike, and none twice. A
 * sloth.db row, a stream incident and the device drawer, each with a
 * U+202E in its title and its detail. Seen red, one at a time, with
 * row_json()'s sloth.db title, the detail page's title and its detail
 * written by web_jw_str() (raw U+202E in /api/alerts, then in
 * /api/alert?id=d90), the drawer's title the same way (raw in
 * /api/device), the stream incident's title kept as it came (raw in
 * /api/alerts), and the stream's detail escaped again on the page
 * (\\x twice). */
static void test_alert_text_display_form(void) {
    char sql[1024];
    snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,ip,hostname,vendor,first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:44','192.0.2.44','cam',NULL,%lld,%lld);"
        "INSERT INTO alerts (rowid,key,first_seen,last_seen,type,sev,title,detail,technique,"
        "match_ip,match_port,count) VALUES"
        " (90,'twin:db',%lld,%lld,%d,1,'Evil twin home\xe2\x80\xae','ssid=evil\xe2\x80\xae"
        "cod','T1557','192.0.2.44',0,3);",
        T - HR, T - 60, T - HR, T - 60, (int)ALERT_TYPE_EVIL_TWIN_PROXIMITY);
    WT_EQ(sdb_exec(g_db, sql), 0);
    char b[1024];
    snprintf(b, sizeof(b),
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"d4e6f8a0b2c4d504\",\"key\":"
        "\"twin:live\",\"title\":\"Twin live\xe3\x85\xa4\",\"detail\":\"ssid=live\xe2\x80\xae"
        "x\",\"sev\":1,\"ty\":%d,\"count\":1}\n", T - 90, (int)ALERT_TYPE_EVIL_TWIN_PROXIMITY);
    feed(b);
    WT_EQ(route(&H, "/api/alerts", ""), 200);
    const char *o = body_of(g_out);
    WT_HAS(o, "\"title\":\"Evil twin home\\\\xe2\\\\x80\\\\xae\"");
    WT_HAS(o, "\"title\":\"Twin live\\\\xe3\\\\x85\\\\xa4\"");
    WT_LACKS(o, "\xe2\x80\xae");
    WT_LACKS(o, "\xe3\x85\xa4");
    WT_LACKS(o, "\\\\\\\\x");               /* never escaped twice */
    WT_EQ(route(&H, "/api/alert", "id=d90"), 200);
    o = body_of(g_out);
    WT_HAS(o, "\"title\":\"Evil twin home\\\\xe2\\\\x80\\\\xae\"");
    WT_HAS(o, "\"detail\":\"ssid=evil\\\\xe2\\\\x80\\\\xaecod\",\"detail_shown\":true");
    WT_LACKS(o, "\xe2\x80\xae");
    WT_LACKS(o, "\\\\\\\\x");
    WT_EQ(route(&H, "/api/alert", Q("d4e6f8a0b2c4d504")), 200);
    o = body_of(g_out);
    WT_HAS(o, "\"title\":\"Twin live\\\\xe3\\\\x85\\\\xa4\"");
    WT_HAS(o, "\"detail\":\"ssid=live\\\\xe2\\\\x80\\\\xaex\",\"detail_shown\":true");
    WT_LACKS(o, "\xe2\x80\xae");
    WT_LACKS(o, "\\\\\\\\x");
    WT_EQ(route(&H, "/api/device/02:00:00:00:00:44", ""), 200);
    o = body_of(g_out);
    WT_HAS(o, "\"title\":\"Evil twin home\\\\xe2\\\\x80\\\\xae\"");
    WT_LACKS(o, "\xe2\x80\xae");
}

/* A key's incidents and count are its totals over every sloth.db row,
 * on its list row and its page alike: a v8 row holds 1 + reopens
 * incidents (#170), and a key with rows before the window is counted
 * over all of them although the list reads only the window. Seen red
 * with web_adb_key_totals()'s sum(1 + reopens) as count(*) (2 in place
 * of 6, on the list and the page) and, apart, with row_json() summing
 * the window's group (key_sum(&t0, ...)) in place of the key's totals
 * (1 incident and x5 on the list, the page still 2 and x12). */
static void test_key_totals_on_list_and_page(void) {
    char sql[1024];
    snprintf(sql, sizeof(sql),
        "INSERT INTO alerts (rowid,key,first_seen,last_seen,type,sev,title,detail,technique,"
        "match_ip,match_port,count,reopens) VALUES"
        " (91,'scan:192.0.2.60',%lld,%lld,0,1,'PORT_SCAN','x','T1046','192.0.2.60',0,4,3),"
        " (92,'scan:192.0.2.60',%lld,%lld,0,1,'PORT_SCAN','x','T1046','192.0.2.60',0,6,1),"
        " (93,'scan:192.0.2.61',%lld,%lld,0,1,'PORT_SCAN','x','T1046','192.0.2.61',0,7,0),"
        " (94,'scan:192.0.2.61',%lld,%lld,0,1,'PORT_SCAN','x','T1046','192.0.2.61',0,5,0);",
        T - 3 * HR, T - 3 * HR + 60, T - 2 * HR, T - 2 * HR + 60,
        T - 10 * DY, T - 10 * DY + 60, T - HR, T - HR + 60);
    WT_EQ(sdb_exec(g_db, sql), 0);
    WT_EQ(route(&H, "/api/alerts", ""), 200);
    const char *b = body_of(g_out);
    const char *r1 = strstr(b, "{\"id\":\"d92\"");
    const char *r2 = strstr(b, "{\"id\":\"d94\"");
    WT_ASSERT(r1 != NULL);
    WT_ASSERT(r2 != NULL);
    long long l1i = r1 ? num_of(r1, "incidents") : -1, l1c = r1 ? num_of(r1, "count") : -1;
    long long l2i = r2 ? num_of(r2, "incidents") : -1, l2c = r2 ? num_of(r2, "count") : -1;
    WT_EQ(l1i, 6);
    WT_EQ(l1c, 10);
    WT_EQ(l2i, 2);
    WT_EQ(l2c, 12);
    WT_EQ(route(&H, "/api/alert", "id=d92"), 200);
    WT_EQ(num_of(body_of(g_out), "incidents"), 6);
    WT_EQ(num_of(body_of(g_out), "incidents"), l1i);
    WT_EQ(num_of(body_of(g_out), "count"), l1c);
    WT_EQ(route(&H, "/api/alert", "id=d94"), 200);
    WT_EQ(num_of(body_of(g_out), "incidents"), l2i);
    WT_EQ(num_of(body_of(g_out), "count"), l2c);
    WT_EQ(num_of(body_of(g_out), "first_seen"), T - 10 * DY);
}

/* The drawer walks a device's alerts a slice at a time and keeps at
 * most 65 keys of one: they are the slice's newest, not the first 65
 * in key order. 70 keys name one device inside a day, the
 * alphabetically first the oldest; the drawer's twelve are the newest
 * twelve. Seen red with the slice's ORDER BY max(last_seen) DESC
 * removed (K69 absent from the twelve, K57 among them). */
static void test_drawer_keeps_a_slices_newest_keys(void) {
    static char sql[16384];
    int o = snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,ip,hostname,vendor,first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:55','192.0.2.55','busy',NULL,%lld,%lld);"
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,technique,"
        "match_ip,match_port,count) VALUES", T - DY, T - 60);
    for (int i = 0; i < 70 && o > 0 && (size_t)o < sizeof(sql); i++)
        o += snprintf(sql + o, sizeof(sql) - (size_t)o,
                      "%s('dev:02:00:00:00:00:55:k%02d',%lld,%lld,0,1,'K%02d','x','T1046',"
                      "NULL,NULL,1)", i ? "," : "", i, T - 2000 + i * 10, T - 2000 + i * 10 + 5, i);
    WT_ASSERT(o > 0 && (size_t)o + 2 < sizeof(sql));
    if (o <= 0 || (size_t)o + 2 >= sizeof(sql)) return;
    snprintf(sql + o, sizeof(sql) - (size_t)o, ";");
    WT_EQ(sdb_exec(g_db, sql), 0);
    WT_EQ(route(&H, "/api/device/02:00:00:00:00:55", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"alerts\":[{\"title\":\"K69\"");
    WT_HAS(b, "\"title\":\"K58\"");
    WT_LACKS(b, "\"title\":\"K57\"");
    WT_HAS(b, "\"alerts_more\":true");
}

void run_alerts_tests(void) {
    WT_RUN(test_page_carries_the_alert_views);
    up();
    WT_RUN(test_list_collapses_and_orders);
    WT_RUN(test_filters_and_paging);
    WT_RUN(test_detail_sections);
    WT_RUN(test_stream_detail);
    WT_RUN(test_key_and_withheld_detail_never_served);
    WT_RUN(test_incident_ids_never_served);
    WT_RUN(test_stream_groups_by_key);
    WT_RUN(test_history_and_drawer_collapse);
    WT_RUN(test_every_type_renders);
    WT_RUN(test_lists_stay_bounded);
    WT_RUN(test_filters_reach_past_the_cap);
    WT_RUN(test_tiles_equal_their_views_on_demo_data);
    down();
    up();
    WT_RUN(test_alert_text_display_form);
    WT_RUN(test_key_totals_on_list_and_page);
    WT_RUN(test_drawer_keeps_a_slices_newest_keys);
    down();
}

#endif
