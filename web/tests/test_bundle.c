/* /api/bundle (web_bundle.h) through the route table, without a
 * socket: a sloth.db generated from sloth's own DDL (sdb_gen.c) on the
 * pinned clock, seeded as test_alerts.c seeds its own (a device named
 * by a deauth flood's key, one holding an alert's address, a cleartext
 * credential whose key and detail carry the username, an SNMP brute
 * force whose detail carries the community), and a live state fed
 * lifecycle records in the shape src/jsonl.c writes them.
 *
 * What the bundle promises and this file holds it to:
 *   - every parameter refused whole, in a word of slothweb's own;
 *   - the spliced members are the routes' bytes, compared byte for
 *     byte, so the bundle cannot carry what the page would not show;
 *   - every registry section is present with data or marked
 *     {"available":false,"reason":<a fixed word>};
 *   - the credential and incident-id tests of test_alerts.c, rerun
 *     against every kind, with the "withheld" entries present. Seen red
 *     under one-line mutants, each restored byte-identical: the alert
 *     page writing e->key as a "key" member (the bundle carried
 *     "alice", "cred:" and a "key" member), writing e->id for e->hid
 *     (it carried an incident_id), and the detail gate opened (it
 *     carried "alice" and "community-secret"). sloth.db's key
 *     ("snmp-brute:...") is a column no reader selects, so no one-line
 *     mutant reaches it; its absence is asserted, not claimed as tested;
 *   - the caps: a device whose address 10,000 records name gets the
 *     ring's 50 and "limits" says the ring was full; the hard cap rolls
 *     optional sections back to too_large and names them, and refuses
 *     the bundle (413) when the required part cannot fit;
 *   - the scope echo and in_scope carried through, page.url null from
 *     the server, and the page's control built from text only. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sloth.h"
#include "web_assets.h"
#include "web_ble.h"
#include "web_bundle.h"
#include "web_frrs.h"
#include "web_ingest.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_routes.h"
#include "wtest.h"

#define T SDB_NOW_T
#define SDB_NOW_T 1792627200LL
#define HR 3600LL
#define DY 86400LL

static char g_out[65536];
/* The bundle's own body (web_resp_t.body_owned), copied out of the
 * route's answer; a route with a static body leaves it empty. */
static char *g_body;
static size_t g_body_len;

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
    free(g_body);
    g_body = NULL;
    g_body_len = 0;
    if (web_route(&rq, h, 1, g_out, sizeof(g_out), &r) != 0) return -1;
    g_out[r.out_len < sizeof(g_out) ? r.out_len : sizeof(g_out) - 1] = '\0';
    if (r.body_owned) {
        g_body = malloc(r.body_len + 1);
        if (g_body) {
            memcpy(g_body, r.body_owned, r.body_len);
            g_body[r.body_len] = '\0';
            g_body_len = r.body_len;
        }
        free(r.body_owned);
    }
    return r.status;
}

static int route(const web_health_t *h, const char *path, const char *query) {
    return route_m(h, path, query, 0);
}

/* The answer's body, wherever it was sent from. */
static const char *answer(void) { return g_body ? g_body : body_of(g_out); }

#ifdef WITH_SQLITE
/* Read helpers for the sloth.db-backed cases below; a WITH_SQLITE=0
 * build has none, and an unused static is a -Werror failure there. */

/* The value of the first member named key after from: the bytes after
 * "key": (NULL when absent). */
static const char *member(const char *from, const char *key) {
    char k[96];
    snprintf(k, sizeof(k), "\"%s\":", key);
    const char *p = from ? strstr(from, k) : NULL;
    return p ? p + strlen(k) : NULL;
}

/* The alert's own page: "page" alone would find the envelope's. */
static const char *alert_page(const char *b) {
    return member(b ? strstr(b, "\"alert\":{\"page\":") : NULL, "page");
}

static size_t vlen(const char *v);

static int count_of(const char *s, const char *needle) {
    int n = 0;
    for (const char *p = s; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}
#endif

/* ── the page ──────────────────────────────────────────────────────── */

/* The control is its own module, included after app.js into the one
 * script, with one call per detail view; it builds nodes from text and
 * copies through the clipboard or the selected-textarea fallback. */
static void test_page_carries_the_control(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "window.SlothBundle = (function () {");
    WT_HAS(p, "  return { mount: mount, fileName: fileName };");
    /* Before #dr-close, so close stays at the right and follows copy in
     * the tab order; appended, both took margin-left:auto and split the
     * row. Seen red with the fifth argument dropped. */
    WT_HAS(p, "    SlothBundle.mount($(\"dr-hd\"), \"device\", mac, scoped, $(\"dr-close\"));");
    WT_LACKS(p, "SlothBundle.mount($(\"dr-hd\"), \"device\", mac, scoped);");
    WT_HAS(p, "if (before && before.parentNode === host) host.insertBefore(box, before);");
    WT_HAS(p, ".dr-hd #dr-note { flex: 1 1 auto; }");
    WT_LACKS(p, ".dr-hd .bundle { margin-left: auto; }");
    /* Inside ad-head, which loading and an error rewrite: no control is
     * left naming the alert before. */
    WT_HAS(p, "    SlothBundle.mount($(\"ad-head\"), \"alert\", j.id, scoped);");
    WT_LACKS(p, "SlothBundle.mount($(\"ad-head\").parentNode");
    WT_HAS(p, "      SlothBundle.mount($(\"l-src\"), \"lookup\", j.q, scoped);");
    WT_HAS(p, "<div class=\"dr-hd\" id=\"dr-hd\">");
    /* Before app.js, so a view app.js opens while the script first runs
     * (an address naming a device) finds the module defined. */
    const char *mod = strstr(p, "window.SlothBundle = (function () {");
    const char *app = strstr(p, "SlothBundle.mount($(\"dr-hd\")");
    WT_ASSERT(mod && app && mod < app);
    /* The copy buttons' ids, as agreed with the slices sharing the views:
     * bundle-btn-drawer, bundle-btn-alert, bundle-btn-lookup. */
    WT_HAS(p, "var SLOT = { device: \"drawer\", alert: \"alert\", lookup: \"lookup\", ble: \"ble\", "
              "platform: \"tacdb\" };");
    WT_HAS(p, "var cid = \"bundle-btn-\" + (");
    /* The BLE drawer's and the TACDB view's hooks are spans that carry
     * the slot's id already: the button takes none, so no id is on the
     * page twice. Seen red with copy.id = cid unconditional. */
    WT_HAS(p, "if (host.id !== cid) copy.id = cid;");
    WT_HAS(p, "<span id=\"bundle-btn-ble\"></span>");
    WT_HAS(p, "<span id=\"bundle-btn-tacdb\"></span>");
    /* The BLE hook carries the scope, as the other views' do: the
     * bundle answers Local as /api/ble does. */
    WT_HAS(p, "SlothBundle.mount(bb, \"ble\", addr, scoped);");
    WT_HAS(p, "mountBundle($(\"bundle-btn-tacdb\"), \"platform\", String(p.id));");
    /* No kind is reserved any more: the word is gone with its branch. */
    WT_LACKS(p, "kind_not_built");
    WT_HAS(p, "el(\"button\", \"\", \"copy JSON\")");
    WT_HAS(p, "el(\"button\", \"\", \"download .json\")");
    WT_HAS(p, "\"/api/bundle?kind=\" + encodeURIComponent(st.kind) + \"&id=\" + encodeURIComponent(st.id)");
    WT_HAS(p, "navigator.clipboard.writeText(text)");
    WT_HAS(p, "document.execCommand(\"copy\")");
    WT_HAS(p, "\"copied (\" + kb(text) + \" KB)\"");
    WT_HAS(p, "\"copy failed, download instead\"");
    /* The clipboard write stays inside the click: fetched ahead on
     * pointer or focus, a promised ClipboardItem otherwise, else a
     * second click; what is kept is keyed on the scoped path, expires,
     * and is dropped on every mount. */
    WT_HAS(p, "copy.addEventListener(\"pointerenter\", prefetch);");
    WT_HAS(p, "copy.addEventListener(\"focus\", prefetch);");
    WT_HAS(p, "navigator.clipboard.write([new window.ClipboardItem({ \"text/plain\": body })])");
    WT_HAS(p, "\"ready: click copy again\"");
    /* Kept a minute, re-armed on a resting or touching pointer: on plain
     * http a first click copies only text already kept. */
    WT_HAS(p, "var FRESH_MS = 60000;");
    WT_HAS(p, "copy.addEventListener(\"pointermove\", prefetch);");
    WT_HAS(p, "copy.addEventListener(\"pointerdown\", prefetch);");
    /* A failed fetch holds the pointer off its request for 10 s (a 404
     * answers in milliseconds: one bundle build per pointermove); a
     * click retries and says the kept error. Seen red with the old
     * prefetch, which had no keptErr() test, restored. */
    WT_HAS(p, "var BACKOFF_MS = 10000;");
    WT_HAS(p, "if (m !== \"stale\") { st.err = m; st.errPath = path; st.errAt = Date.now(); }");
    WT_HAS(p, "if (!st.busy && ready(st) === null && keptErr(st) === null) load(st)");
    WT_LACKS(p, "if (!st.busy && ready(st) === null) load(st)");
    WT_HAS(p, "errText(e) + \"; retrying\"");
    /* The note names the text written, not st.text, which a mount
     * before write() settles has nulled (kb(null) threw). Seen red with
     * copied(st.text, true) restored. */
    WT_HAS(p, "got = s.text;");
    WT_HAS(p, "copied(got, true);");
    WT_LACKS(p, "copied(st.text, true)");
    WT_HAS(p, "st.path === pathOf(st) && Date.now() - st.at < FRESH_MS");
    WT_HAS(p, "st.text = null; st.path = \"\"; st.at = 0; st.ts = 0;");
    WT_HAS(p, "a.download = name;");
    WT_HAS(p, "st.text = JSON.stringify(j, null, 1);");
    WT_HAS(p, "j.page.url = location.href;");
    WT_HAS(p, "j.page.view = viewWord();");
    WT_HAS(p, "\"slothweb-\" + kind + \"-\" + safe + \"-\" + ts + \".json\"");
    /* Text only: the module's nodes are made and filled, never parsed. */
    const char *m = strstr(p, "window.SlothBundle = (function () {");
    WT_ASSERT(m != NULL);
    if (m) {
        WT_LACKS(m, "innerHTML");
        WT_LACKS(m, "insertAdjacentHTML");
        WT_LACKS(m, "setAttribute(");
        WT_HAS(m, "e.textContent = String(text);");
    }
}

/* web_jw_rawn() is for our own writers' output only: the bundle is its
 * one caller. Seen red with a web_jw_rawn(w, "", 0) added to
 * web_live.c. */
static void test_rawn_has_one_caller(void) {
    DIR *d = opendir("web/src");
    WT_ASSERT(d != NULL);
    if (!d) return;
    struct dirent *e;
    int callers = 0;
    while ((e = readdir(d)) != NULL) {
        size_t n = strlen(e->d_name);
        if (n < 3 || strcmp(e->d_name + n - 2, ".c")) continue;
        char path[300];
        snprintf(path, sizeof(path), "web/src/%s", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char line[1024];
        while (fgets(line, sizeof(line), f))
            if (strstr(line, "web_jw_rawn(") && !strstr(line, "void web_jw_rawn(")) {
                if (strcmp(e->d_name, "web_bundle.c")) {
                    fprintf(stderr, "    %s: %s", e->d_name, line);
                    callers++;
                }
            }
        fclose(f);
    }
    closedir(d);
    WT_EQ(callers, 0);
}

#ifndef WITH_SQLITE

/* Without SQLite the stream alone answers; sloth.db is "unbuilt". */
void run_bundle_tests(void) {
    WT_RUN(test_page_carries_the_control);
    WT_RUN(test_rawn_has_one_caller);
    web_live_t *l = calloc(1, sizeof(*l));
    WT_ASSERT(l != NULL);
    if (!l) return;
    web_live_init(l, "unix:/t/s.sock");
    web_live_sock_connected(l, 0);
    web_feed_t f;
    memset(&f, 0, sizeof(f));
    web_feed_reset(&f);
    const char rec[] = "{\"type\":\"alert.create\",\"ts\":1,\"incident_id\":\"aaaa\","
                       "\"ty\":0,\"sev\":1,\"title\":\"PORT_SCAN\",\"key\":\"scan:x\","
                       "\"match_ip\":\"192.0.2.9\"}\n"
                       "{\"type\":\"dns\",\"ts\":2,\"qname\":\"a.example.org\",\"src\":\"192.0.2.9\"}\n";
    web_feed_bytes(&f, l, rec, strlen(rec), 1000);
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = 100;
    h.live = l;
    WT_EQ(route(&h, "/api/bundle", "kind=device&id=02:00:00:00:00:12"), 200);
    WT_HAS(answer(), "{\"bundle_schema\":\"1.0.0\",\"kind\":\"device\",\"id\":\"02:00:00:00:00:12\"");
    WT_HAS(answer(), "\"sloth_db\":{\"state\":\"none\"");
    WT_HAS(answer(), "\"device\":{\"drawer\":{\"mac\":\"02:00:00:00:00:12\"");
    WT_HAS(answer(), "\"records_recent\":{\"available\":true,");
    char q[64];
    snprintf(q, sizeof(q), "kind=alert&id=s%s", l->inc[0].hid);
    WT_EQ(route(&h, "/api/bundle", q), 200);
    WT_HAS(answer(), "\"alert\":{\"page\":{\"id\":\"s");
    WT_LACKS(answer(), "aaaa");
    WT_HAS(answer(), "\"lookup\":{\"q\":\"192.0.2.9\"");
    WT_EQ(route(&h, "/api/bundle", "kind=alert&id=d4"), 503);
    WT_HAS(answer(), "{\"error\":\"no_sloth_db\"}");
    web_live_destroy(l);
    free(l);
}

#else

#include <sqlite3.h>
#include "sdb_gen.h"
#include "wt_tmp.h"

static char g_dir[TEST_TMP_MAX];
static char g_db[128];
static web_slothdb_t sdb;
static web_m4_t m4;
static web_health_t H;
static web_live_t *g_live;
static web_feed_t g_feed;
static web_store_t g_store;
static int g_have_store;
static web_frrs_t g_frrs;
static web_ble_t g_ble;

static void feed(const char *s) {
    web_feed_bytes(&g_feed, g_live, s, strlen(s), 1000);
}

/* A BLE advertiser as the emitter writes its ble_device line (the
 * shape test_ble.c's dev_line() builds), into the BLE table. */
#define BLE_ADDR "02:de:00:00:00:21"
static void ble_seed(void) {
    char line[2048];
    snprintf(line, sizeof(line),
             "{\"type\":\"ble_device\",\"ts\":%lld,\"addr\":\"" BLE_ADDR "\",\"addr_type\":0,"
             "\"sensor\":\"ble\",\"iface\":\"bluetooth-monitor\",\"adapter\":0,\"sampled\":0,"
             "\"channel\":-1,\"last_pdu\":\"ADV_IND\",\"pdu_mask\":1,\"name\":\"kettle\","
             "\"name_complete\":1,\"uuid16\":-1,\"mfr_id\":-1,\"mfr_subtype\":-1,"
             "\"svc_data_uuid16\":-1,\"appearance\":-1,\"hid\":0,\"tx_power\":-128,"
             "\"flags\":-1,\"has_rssi\":1,\"rssi\":-50,\"rssi_best\":-45,\"adv_count\":100,"
             "\"watch_category\":\"\",\"ext_adv\":0,\"primary_phy\":0,\"secondary_phy\":0,"
             "\"adv_sid\":-1,\"first_seen\":%lld,\"last_seen\":%lld}",
             T - 20, T - 500, T - 20);
    static web_jrec_t r;
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_ble_record(&g_ble, &r, 1000);
}


/* sloth's incident_ids in the stream below: never on the wire. */
#define IA "a1f0c3e5d7b9a201"
#define IB "b2e4c6a8f0d1b302"
#define IC "c3d5e7f9a1b3c403"

/* The page's id of a stream incident ("s" and slothweb's handle), by
 * sloth's incident_id, read off web_live_t. */
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

static const char CRED_KEY[] = "cred:10.0.0.1:10.0.0.9:21:FTP:alice-secret-user:0123456789abcdef";

/* The rows, by rowid, as test_alerts.c has them:
 *   3-7   scan:192.0.2.50 today
 *   10    deauth:02:00:00:00:00:12@02:00:00:00:00:a1: device ...:12
 *   11    smb1:192.0.2.18, match_ip 192.0.2.18: device ...:18 by address
 *   20-21 CLEARTEXT_CRED, the username in the key and the detail
 *   22    SNMP_COMMUNITY_BRUTE, the community in the detail */
static int seed(void) {
    char sql[8192];
    int n = snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,ip,hostname,vendor,first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:12','192.0.2.12','laptop',NULL,%lld,%lld),"
        " ('02:00:00:00:00:18','192.0.2.18','nas',NULL,%lld,%lld);"
        "INSERT INTO arp (ip,mac,iface,first_seen,last_seen) VALUES"
        " ('192.0.2.18','02:00:00:00:00:18','eth0',%lld,%lld);"
        "INSERT INTO alerts (rowid,key,first_seen,last_seen,type,sev,title,detail,technique,"
        "match_ip,match_port,count) VALUES"
        " (3,'scan:192.0.2.50',%lld,%lld,0,0,'PORT_SCAN','192.0.2.50 scanned 8 distinct ports',"
        "'T1046','192.0.2.50',0,8),"
        " (4,'scan:192.0.2.50',%lld,%lld,0,1,'PORT_SCAN','192.0.2.50 scanned 8 distinct ports',"
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
        "'10.0.0.7',161,9);"
        "INSERT INTO device_positions (mac,last_seen,lat,lon,acc_m,rssi) VALUES"
        " ('02:00:00:00:00:12',%lld,48.5000000,11.2500000,7.5,-61);"
        "INSERT INTO sensor_positions (last_seen,lat,lon,alt_m,acc_m,loc_src) VALUES"
        " (%lld,48.5000000,11.2500000,500,7.5,'gps');",
        T - 10 * DY, T - 60, T - 10 * DY, T - 60,
        T - 10 * DY, T - 60,
        T - 5 * HR, T - 5 * HR + 300, T - 5 * HR + 900, T - 5 * HR + 1200,
        T - 5 * HR + 3600, T - 5 * HR + 3900,
        T - 2 * HR, T - HR,
        T - 4 * HR, T - 1800,
        CRED_KEY, T - 2 * DY, T - 2 * DY + 60, CRED_KEY, T - HR, T - 30 * 60,
        T - 900, T - 600, T - 120, T - 120);
    if (n < 0 || (size_t)n >= sizeof(sql)) return -1;
    return sdb_exec(g_db, sql);
}

/* The stream: a scan open (not in sloth.db), the deauth flood resolved
 * with a pcap (in sloth.db too), a cleartext credential open with the
 * username in its key and detail, then sensor_health and a few records
 * naming device ...:12 and its address. */
static void stream(void) {
    char b[4096];
    snprintf(b, sizeof(b),
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"" IA "\",\"key\":"
        "\"scan:192.0.2.77\",\"title\":\"PORT_SCAN\",\"detail\":\"192.0.2.77 scanned 12"
        " distinct ports\",\"sev\":1,\"ty\":0,\"count\":3,\"observations\":2,"
        "\"first_detected\":%lld,\"technique\":\"T1046\",\"match_ip\":\"192.0.2.77\","
        "\"match_port\":0}\n"
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"" IB "\",\"key\":"
        "\"deauth:02:00:00:00:00:12@02:00:00:00:00:a1\",\"title\":\"DEAUTH_FLOOD\","
        "\"detail\":\"victim=02:00:00:00:00:12 bssid=02:00:00:00:00:a1 observed 6 frames\","
        "\"sev\":1,\"ty\":1,\"count\":1,\"loc\":{\"lat\":-33.8688000,\"lon\":151.2093000,"
        "\"acc_m\":6.5,\"src\":\"gps\",\"ts\":%lld}}\n"
        "{\"type\":\"alert.escalate\",\"ts\":%lld,\"incident_id\":\"" IB "\",\"key\":"
        "\"deauth:02:00:00:00:00:12@02:00:00:00:00:a1\",\"title\":\"DEAUTH_FLOOD\","
        "\"detail\":\"victim=02:00:00:00:00:12 bssid=02:00:00:00:00:a1 observed 40 frames\","
        "\"sev\":2,\"prev_sev\":1,\"ty\":1,\"count\":5,"
        "\"pcap_path\":\"/var/lib/sloth/pcap/x.pcap\"}\n"
        "{\"type\":\"alert.resolve\",\"ts\":%lld,\"incident_id\":\"" IB "\",\"key\":"
        "\"deauth:02:00:00:00:00:12@02:00:00:00:00:a1\",\"title\":\"DEAUTH_FLOOD\","
        "\"sev\":2,\"ty\":1,\"count\":6,\"reason\":\"expired\"}\n"
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"" IC "\",\"key\":\"%s\","
        "\"title\":\"CLEARTEXT_CRED\",\"detail\":\"FTP user alice-secret-user in the clear on"
        " FTP -> 10.0.0.9:21\",\"sev\":1,\"ty\":27,\"count\":1,\"match_ip\":\"10.0.0.1\","
        "\"match_port\":21}\n"
        "{\"type\":\"sensor_health\",\"ts\":%lld,\"capture_iface\":\"eth0\",\"capture_open\":1,"
        "\"capture_running\":1,\"capture_linktype\":1,\"monitor_iface\":\"wlan1mon\","
        "\"monitor_open\":1,\"monitor_running\":1,\"scope\":\"all\",\"scope_not_enforced\":0}\n"
        "{\"type\":\"dns\",\"ts\":%lld,\"qname\":\"laptop.example.org\",\"src\":\"192.0.2.12\"}\n"
        "{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":\"02:00:00:00:00:12\",\"ssid\":\"HomeNet\"}\n"
        "{\"type\":\"dns\",\"ts\":%lld,\"qname\":\"other.example.org\",\"src\":\"192.0.2.99\"}\n",
        T - 600, T - 700, T - 3600, T - 3602, T - 3000, T - 120, T - 300, CRED_KEY,
        T - 10, T - 9, T - 8, T - 7);
    feed(b);
}

static void up(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-bundle-XXXXXX", test_tmpdir());
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
    /* slothweb's own store and the FRRS module on it, and the BLE
     * table: the routes the bundle's newer sections splice. */
    char sp[TEST_TMP_MAX + 32], err[512];
    snprintf(sp, sizeof(sp), "%s/slothweb.db", g_dir);
    g_have_store = web_store_open(&g_store, sp, err, sizeof(err)) == 0;
    WT_ASSERT(g_have_store);
    WT_EQ(web_frrs_init(&g_frrs, g_have_store ? &g_store : NULL, NULL, 1, err, sizeof(err)), 0);
    m4.frrs = &g_frrs;
    WT_EQ(web_ble_init(&g_ble, 0), 0);
    ble_seed();
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.uptime_s = 42;
    H.now_ms = 1000;
    H.m4 = &m4;
    H.live = g_live;
    H.ble = &g_ble;
}

static void down(void) {
    web_frrs_destroy(&g_frrs);
    if (g_have_store) web_store_close(&g_store);
    g_have_store = 0;
    web_ble_destroy(&g_ble);
    web_slothdb_destroy(&sdb);
    web_live_destroy(g_live);
    free(g_live);
    free(g_body);
    g_body = NULL;
    test_rm_tree(g_dir);
}

/* Every parameter checked before anything is read, each refusal a word
 * of slothweb's own; a HEAD a 405 as /api/alert's. */
static void test_parameters_refused_whole(void) {
    static const struct { const char *query; int status; const char *word; } R[] = {
        { "", 400, "missing_kind" },
        { "id=1", 400, "missing_kind" },
        { "kind=x&id=1", 400, "bad_kind" },
        { "kind=ble&id=1", 400, "bad_mac" },
        { "kind=ble&id=02:de:00:00:00:99", 404, "not_found" },
        { "kind=platform&id=x", 400, "bad_id" },
        { "kind=platform&id=0", 400, "bad_id" },
        { "kind=platform&id=01", 400, "bad_id" },
        { "kind=platform&id=99999999999999", 400, "bad_id" },
        { "kind=platform&id=9", 404, "no_such_platform" },
        { "kind=device", 400, "missing_id" },
        { "kind=device&id=zz", 400, "bad_mac" },
        { "kind=device&id=02:00:00:00:00:1g", 400, "bad_mac" },
        { "kind=alert&id=x1", 400, "bad_id" },
        { "kind=alert&id=d0", 400, "bad_id" },
        { "kind=alert&id=s", 400, "bad_id" },
        /* Decoded once, not twice: d1%2530 is "d1%30", not d10. */
        { "kind=alert&id=d1%2530", 400, "bad_id" },
        { "kind=alert&id=d1%26x%3D1", 400, "bad_id" },
        { "kind=lookup&id=nope", 400, "bad_lookup" },
        { "kind=device&id=02:00:00:00:00:12&x=1", 400, "unknown_parameter" },
        { "kind=device&kind=device&id=02:00:00:00:00:12", 400, "repeated_parameter" },
        { "kind=&id=02:00:00:00:00:12", 400, "empty_value" },
        { "kind=alert&id=s0", 404, "no_such_alert" },
        { "kind=alert&id=d99999", 404, "no_such_alert" },
        { "scope=bogus&kind=device&id=02:00:00:00:00:12", 400, "bad_scope" },
    };
    for (size_t i = 0; i < sizeof(R) / sizeof(R[0]); i++) {
        int st = route(&H, "/api/bundle", R[i].query);
        char want[80];
        snprintf(want, sizeof(want), "\"error\":\"%s\"", R[i].word);
        if (st != R[i].status || !strstr(answer(), want))
            fprintf(stderr, "    ?%s: %d %s\n", R[i].query, st, answer());
        WT_EQ(st, R[i].status);
        WT_HAS(answer(), want);
        /* The bundle's own heap body, its errors too; a bad scope is
         * the router's, refused before the bundle runs. */
        if (strcmp(R[i].word, "bad_scope")) WT_ASSERT(g_body != NULL);
    }
    char longq[600];
    memset(longq, 'a', sizeof(longq) - 1);
    memcpy(longq, "kind=", 5);
    longq[sizeof(longq) - 1] = '\0';
    WT_EQ(route(&H, "/api/bundle", longq), 400);
    WT_HAS(answer(), "\"error\":\"query_too_long\"");
    WT_EQ(route_m(&H, "/api/bundle", "kind=device&id=02:00:00:00:00:12", 1), 405);
    WT_HAS(g_out, "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\n");
}

/* The envelope, in order, then the kind's section, then the aids. */
static void test_device_bundle_shape(void) {
    WT_EQ(route(&H, "/api/bundle", "kind=device&id=02-00-00-00-00-12"), 200);
    const char *b = answer();
    WT_HAS(g_out, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n");
    WT_HAS(g_out, "Cache-Control: no-store\r\n");
    char cl[64];
    snprintf(cl, sizeof(cl), "Content-Length: %zu\r\n", g_body_len);
    WT_HAS(g_out, cl);
    WT_HAS(b, "{\"bundle_schema\":\"" WEB_BUNDLE_SCHEMA "\",\"kind\":\"device\","
              "\"id\":\"02:00:00:00:00:12\",\"generated_at\":{\"iso\":\"2026-10-22T00:00:00Z\","
              "\"unix\":1792627200},\"server\":{\"timezone\":{\"name\":\"UTC\",\"utc_offset_s\":0},"
              "\"slothweb\":{");
    /* No host name: no page shows it, and a bundle is made to be pasted
     * into a third party's service (seen red with server.host and
     * host_is written back). */
    WT_LACKS(b, "\"host_is\":");
    /* sloth's version, as include/sloth.h has it, and the page's build. */
    WT_HAS(b, "\"slothweb\":{\"build_version\":\"" SLOTH_VERSION "\",\"page_etag\":");
    WT_LACKS(b, "\"milestone\":");
    WT_HAS(b, "\"server.slothweb.build_version\":\"the sloth source tree slothweb was built from");
    WT_HAS(b, "\"uptime_s\":42}");
    WT_HAS(b, web_page_etag);        /* carries its own quotes */
    WT_HAS(b, ",\"sensor\":{\"socket\":\"connected\",\"socket_spec\":\"unix:/test/sloth.sock\","
              "\"state\":\"ok\",\"health_age_s\":0,\"health_ts\":");
    WT_HAS(b, "\"capture\":{\"iface\":\"eth0\",\"linktype\":1,\"open\":1,\"running\":1,\"exit\":\"\"},"
              "\"monitor\":{\"iface\":\"wlan1mon\",\"open\":1,\"running\":1,\"exit\":\"\","
              "\"monitor_only\":false,\"ip_capture_on_radio\":false,\"radios\":[\"wlan1mon\"]},"
              "\"launch_scope\":{\"scope\":\"all\",\"not_enforced\":0},"
              "\"ble_scan\":{\"available\":false,\"reason\":\"not_kept\"}");
    WT_HAS(b, "\"alerts_open\":{\"low\":0,\"warn\":2,\"crit\":0,\"overflow\":false}}");
    WT_HAS(b, ",\"sloth_version\":{\"available\":false,\"reason\":\"not_kept\"");
    WT_HAS(b, ",\"site_label\":{\"available\":false,\"reason\":\"not_built\"");
    WT_HAS(b, ",\"sloth_db\":{\"state\":\"open\",\"schema\":");
    WT_HAS(b, "\"stale_after_s\":600}");
    WT_HAS(b, ",\"scope_in_effect\":{\"scope\":\"hybrid\",\"given\":false,"
              "\"ip_capture_on_radio\":false,\"monitor_ifaces\":[\"wlan1mon\"],"
              "\"excludes\":\"nothing: every source\"}");
    WT_HAS(b, ",\"page\":{\"url\":null,\"view\":null}");
    WT_HAS(b, ",\"withheld\":[{\"field\":\"alert.key, alert.incident_id\",");
    WT_HAS(b, "{\"field\":\"device.drawer.alerts[].detail\",");
    WT_HAS(b, ",\"device\":{\"drawer\":{\"mac\":\"02:00:00:00:00:12\",\"now\":1792627200,"
              "\"db\":\"open\",");
    /* The optional sections, in registry order, after the drawer. */
    const char *d = strstr(b, "\"drawer\":");
    WT_ASSERT(d != NULL);
    if (!d) return;
    /* Past the drawer: the drawer itself carries vendor_research. */
    d += strlen("\"drawer\":");
    d += vlen(d);
    const char *s1 = strstr(d, ",\"signal_history\":{\"available\":false,\"reason\":\"not_built\"}");
    const char *s2 = strstr(d, ",\"distance\":{\"available\":false,\"reason\":\"not_kept\"}");
    const char *s3 = strstr(d, ",\"records_recent\":{\"available\":true,\"source\":\"ticker ring");
    /* The drawer's own vendor research and the FRRS record are data now
     * (test_sections_are_the_routes_bytes holds their bytes). */
    const char *s4 = strstr(d, "},\"vendor_research\":{\"found\":");
    const char *s5 = strstr(d, ",\"frrs\":{");
    const char *s6 = strstr(d, ",\"triage\":{\"available\":false,\"reason\":\"not_built\"}");
    WT_ASSERT(s1 && s2 && s3 && s4 && s5 && s6);
    WT_ASSERT(s1 && s2 && s3 && s4 && s5 && s6 && s1 < s2 && s2 < s3 && s3 < s4 &&
              s4 < s5 && s5 < s6);
    /* The records naming the device: its MAC and its address, newest
     * first; the other host's query is not among them (seen red with
     * every record listed). The deauth alert names the MAC only in its
     * detail, free text, and has no match_ip: not matched. */
    WT_HAS(b, "\"matched\":2,\"by_type\":{\"probe_client\":1,\"dns\":1},"
              "\"records\":[{\"seq\":8,\"type\":\"probe_client\",");
    WT_HAS(b, "\"text\":\"HomeNet  02:00:00:00:00:12\"");
    WT_HAS(b, "\"text\":\"laptop.example.org  192.0.2.12\"");
    WT_LACKS(b, "other.example.org");
    /* The aids, last. */
    const char *g = strstr(b, ",\"glossary\":{\"bundle_schema\":");
    const char *pr = strstr(b, ",\"prompt\":\"You are analysing a JSON bundle copied from slothweb");
    const char *li = strstr(b, ",\"limits\":{\"hard_cap_bytes\":524288,");
    WT_ASSERT(g && pr && li && g < pr && pr < li);
    WT_HAS(b, "\"read_budget_ms_per_read\":250,\"reads\":[{\"what\":\"device\",\"ms\":");
    WT_HAS(b, "{\"name\":\"device.drawer.ssids\",\"cap\":24,\"cut\":false}");
    WT_HAS(b, "{\"name\":\"device.drawer.alerts\",\"cap\":12,\"cut\":false,\"reached\":null}");
    WT_HAS(b, "{\"name\":\"device.records_recent\",\"cap\":50,\"cut\":false,\"ring_records\":");
    WT_HAS(b, "\"nesting\":\"alert.device and lookup.device are the drawer answer only");
    WT_ASSERT(g_body_len >= 2 && !strcmp(b + g_body_len - 2, "}\n"));
    /* Every glossary key is a string: the aid is a flat object. */
    const char *gl = member(b, "glossary");
    WT_ASSERT(gl && gl[0] == '{');
    WT_HAS(gl, "\"sev\":\"0 low, 1 warn, 2 crit (sloth\\u0027s severity)\"");
    WT_HAS(gl, "\"available:false\":\"the section\\u0027s data is not in this bundle; reason: not_built");
}

/* The spliced members are the routes' bytes: /api/device/{mac},
 * /api/alert?id= and /api/lookup?q= answered on their own, their
 * trailing newline dropped, are found verbatim in the bundle. Seen red
 * with the splice re-rendering "now" (a copy made a second later). */
static void test_spliced_answers_are_byte_identical(void) {
    char *dev = NULL, *al = NULL, *lk = NULL, *dev18 = NULL;
    WT_EQ(route(&H, "/api/device/02:00:00:00:00:12", ""), 200);
    dev = strdup(body_of(g_out));
    WT_EQ(route(&H, "/api/alert", "id=d10"), 200);
    al = strdup(body_of(g_out));
    WT_EQ(route(&H, "/api/lookup", "q=02:00:00:00:00:18"), 200);
    lk = strdup(body_of(g_out));
    WT_EQ(route(&H, "/api/device/02:00:00:00:00:18", ""), 200);
    dev18 = strdup(body_of(g_out));
    WT_ASSERT(dev && al && lk && dev18);
    if (!dev || !al || !lk || !dev18) { free(dev); free(al); free(lk); free(dev18); return; }
    size_t nd = strlen(dev) - 1, na = strlen(al) - 1, nl = strlen(lk) - 1, n18 = strlen(dev18) - 1;
    WT_ASSERT(dev[nd] == '\n' && al[na] == '\n' && lk[nl] == '\n');

    WT_EQ(route(&H, "/api/bundle", "kind=device&id=02:00:00:00:00:12"), 200);
    const char *v = member(answer(), "drawer");
    WT_ASSERT(v && !memcmp(v, dev, nd) && v[nd] == ',');

    WT_EQ(route(&H, "/api/bundle", "kind=alert&id=d10"), 200);
    v = alert_page(answer());
    WT_ASSERT(v && !memcmp(v, al, na) && v[na] == ',');
    /* #179: so alert.page reads as the page does, observations,
     * incidents and the severity history ahead of count, every name as
     * it was (seen red with count also written ahead of observations in
     * web_alert_route()). */
    if (v) {
        const char *o = strstr(v, ",\"observations\":"), *in = strstr(v, ",\"incidents\":");
        const char *sh = strstr(v, ",\"sev_history\":[{"), *c = strstr(v, ",\"count\":");
        WT_ASSERT(o && in && sh && c && o < c && in < c && sh < c);
    }
    WT_HAS(answer(), "\"confidence\":\"the rule");
    WT_HAS(answer(), "\"rule_reason\":\"the rule");
    /* The alert names device ...:12 by its key: its drawer, nested,
     * after the page (the page's own "device" member is inside it). */
    const char *nested = v ? member(v + na, "device") : NULL;
    WT_ASSERT(nested && !memcmp(nested, dev, nd) && nested[nd] == ',');
    WT_HAS(answer(), "\"reads\":[{\"what\":\"alert\",\"ms\":");
    WT_HAS(answer(), "},{\"what\":\"alert.device\",\"ms\":");
    WT_HAS(answer(), "{\"name\":\"alert.page.history.runs\",\"cap\":100,\"cut\":false}");
    WT_HAS(answer(), "{\"name\":\"alert.device.alerts\",\"cap\":12,");
    /* No bundle inside a bundle: the nested drawer has no sections
     * (seen red with a records_recent row added to the alert kind). */
    WT_EQ(count_of(answer(), "\"records_recent\":"), 0);
    WT_EQ(count_of(answer(), "\"records_around\":"), 1);
    WT_EQ(count_of(answer(), "\"glossary\":"), 1);

    WT_EQ(route(&H, "/api/bundle", "kind=lookup&id=02-00-00-00-00-18"), 200);
    WT_HAS(answer(), "\"kind\":\"lookup\",\"id\":\"02:00:00:00:00:18\",");
    v = member(answer(), "card");
    WT_ASSERT(v && !memcmp(v, lk, nl) && v[nl] == ',');
    nested = v ? member(v + nl, "device") : NULL;
    WT_ASSERT(nested && !memcmp(nested, dev18, n18) && nested[n18] == '}');
    /* An address no device holds: the card alone, the drawer marked. */
    WT_EQ(route(&H, "/api/bundle", "kind=lookup&id=192.0.2.99"), 200);
    WT_HAS(answer(), "\"lookup\":{\"card\":{\"q\":\"192.0.2.99\",\"kind\":\"ip\",");
    v = member(answer(), "card");
    const char *dv = v ? strstr(v, ",\"device\":null") : NULL;
    WT_ASSERT(dv != NULL);
    WT_HAS(answer(), "},\"device\":{\"available\":false,\"reason\":\"no_data\"}},\"glossary\":{");
    free(dev); free(al); free(lk); free(dev18);
}

/* The end of the JSON value at v, written here apart from the bundle's
 * own walker so the test does not borrow what it checks: strings
 * skipped whole, brackets counted. */
static size_t vlen(const char *v) {
    int depth = 0;
    const char *p = v;
    for (; *p; p++) {
        if (*p == '"') {
            for (p++; *p && *p != '"'; p++) if (*p == '\\' && p[1]) p++;
            if (!*p) break;
            if (!depth) return (size_t)(p + 1 - v);
        } else if (*p == '{' || *p == '[') {
            depth++;
        } else if (*p == '}' || *p == ']') {
            if (!depth) break;
            if (!--depth) return (size_t)(p + 1 - v);
        } else if (*p == ',' && !depth) {
            break;
        }
    }
    return (size_t)(p - v);
}

/* The top-level member name of the object at obj (*n its length). */
static const char *top(const char *obj, const char *name, size_t *n) {
    if (!obj || *obj != '{') return NULL;
    const char *p = obj + 1;
    while (*p == '"') {
        const char *k = p + 1, *ke = strchr(k, '"');
        if (!ke || ke[1] != ':') return NULL;
        const char *v = ke + 2;
        size_t l = vlen(v);
        if ((size_t)(ke - k) == strlen(name) && !strncmp(k, name, (size_t)(ke - k))) {
            *n = l;
            return v;
        }
        if (v[l] != ',') return NULL;
        p = v + l + 1;
    }
    return NULL;
}

/* A route's answer on its own, trailing newline dropped, into a fresh
 * string (NULL when the status is not want). */
static char *own(const char *path, const char *query, int want) {
    int st = route(&H, path, query);
    if (st != want) fprintf(stderr, "    ?%s?%s: %d %s\n", path, query, st, answer());
    WT_EQ(st, want);
    if (st != want) return NULL;
    char *b = strdup(answer());
    if (b && *b && b[strlen(b) - 1] == '\n') b[strlen(b) - 1] = '\0';
    return b;
}

/* The section name of the kind's object in the answer now, as bytes
 * equal to want (want_n of them). */
static int section_is(const char *kind, const char *name, const char *want, size_t want_n) {
    size_t n = 0;
    const char *k = top(answer(), kind, &n);
    const char *v = top(k, name, &n);
    int ok = v && want && n == want_n && !memcmp(v, want, n);
    if (!ok) fprintf(stderr, "    %s.%s: %.*s\n    want %.*s\n", kind, name, v ? (int)(n > 160 ? 160 : n) : 0,
                     v ? v : "", (int)(want_n > 160 ? 160 : want_n), want ? want : "");
    return ok;
}

/* A POST as the server hands it to the router, from the page's origin. */
static int post(const char *path, const char *body) {
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "%s", path);
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    rq.is_post = 1;
    snprintf(rq.origin, sizeof(rq.origin), "http://127.0.0.1:8770");
    rq.origin_count = 1;
    snprintf(rq.ctype, sizeof(rq.ctype), "application/json");
    rq.ctype_count = 1;
    rq.body = body;
    rq.body_len = strlen(body);
    rq.content_length = (long long)rq.body_len;
    snprintf(rq.peer, sizeof(rq.peer), "127.0.0.1");
    memset(&r, 0, sizeof(r));
    if (web_route(&rq, &H, 1, g_out, sizeof(g_out), &r) != 0) return -1;
    g_out[r.out_len < sizeof(g_out) ? r.out_len : sizeof(g_out) - 1] = '\0';
    return r.status;
}

/* The sections whose data main's later slices brought are the owning
 * routes' bytes, never a re-rendering: the FRRS record as
 * /api/frrs/report and /api/frrs/report/alert answer it, the triage
 * history as /api/frrs/history does, and the drawer's vendor research
 * and the alert page's assessment and proof lifted out of the primary
 * answer whole. */
static void test_sections_are_the_routes_bytes(void) {
    char *fr = own("/api/frrs/report", "kind=sta&addr=02:00:00:00:00:12", 200);
    char *dv = own("/api/device/02:00:00:00:00:12", "", 200);
    WT_EQ(route(&H, "/api/bundle", "kind=device&id=02:00:00:00:00:12"), 200);
    WT_ASSERT(section_is("device", "frrs", fr, fr ? strlen(fr) : 0));
    size_t n = 0;
    const char *vr = top(dv, "vendor_research", &n);
    WT_ASSERT(vr != NULL);
    WT_ASSERT(section_is("device", "vendor_research", vr, n));
    WT_HAS(answer(), ",{\"what\":\"device.frrs\",\"ms\":");
    /* Where the sensor was: /api/positions as the drawer's scatter asks
     * it, the seeded sample and track point in it (seen red with the
     * device row's fill put back to NULL, "not_built"). */
    char *ps = own("/api/positions", "mac=02:00:00:00:00:12", 200);
    WT_HAS(ps, "\"lat\":48.5000000");
    WT_EQ(route(&H, "/api/bundle", "kind=device&id=02:00:00:00:00:12"), 200);
    WT_ASSERT(section_is("device", "location", ps, ps ? strlen(ps) : 0));
    WT_HAS(answer(), ",{\"what\":\"device.location\",\"ms\":");
    free(fr); free(dv); free(ps);

    char *al = own("/api/alert", "id=d10", 200);
    char *fa = own("/api/frrs/report/alert", "id=d10", 200);
    char *th = own("/api/frrs/history", "id=d10", 200);
    WT_EQ(route(&H, "/api/bundle", "kind=alert&id=d10"), 200);
    WT_ASSERT(section_is("alert", "frrs", fa, fa ? strlen(fa) : 0));
    WT_ASSERT(section_is("alert", "triage", th, th ? strlen(th) : 0));
    const char *as = top(al, "assessment", &n);
    /* DEAUTH_FLOOD has its assessment in docs/wiki/alert-assessments. */
    WT_ASSERT(as && *as == '{');
    WT_ASSERT(section_is("alert", "assessment", as, n));
    /* The proof block: the page's captures, its note and its evidence,
     * in that order and nothing else (no frames: a pcap's bytes are
     * /api/pcap's, never the bundle's). */
    char ev[24 * 1024];
    size_t en = 0;
    static const char *const M[] = { "captures", "captures_note", "evidence" };
    en += (size_t)snprintf(ev + en, sizeof(ev) - en, "{");
    for (int i = 0; i < 3; i++) {
        const char *v = top(al, M[i], &n);
        WT_ASSERT(v != NULL);
        if (!v || en + n + 32 > sizeof(ev)) break;
        en += (size_t)snprintf(ev + en, sizeof(ev) - en, "%s\"%s\":%.*s", i ? "," : "", M[i],
                               (int)n, v);
    }
    en += (size_t)snprintf(ev + en, sizeof(ev) - en, "}");
    WT_ASSERT(section_is("alert", "evidence", ev, en));
    /* The alert page's own stamp, lifted whole (seen red with the
     * alert row's fill put back to NULL). */
    const char *lc = top(al, "loc", &n);
    WT_ASSERT(lc && *lc == '{');
    if (lc) WT_ASSERT(!strncmp(lc, "{\"lat\":-33.8688000,", 19));
    WT_ASSERT(section_is("alert", "location", lc, n));
    WT_HAS(answer(), "{\"what\":\"alert.frrs\",\"ms\":");
    WT_HAS(answer(), "{\"what\":\"alert.triage\",\"ms\":");
    free(al); free(fa); free(th);

    /* A decision on the alert is in the next bundle, as the history
     * route says it; cleared again for the tests after this one. */
    WT_EQ(post("/api/frrs/triage", "{\"id\":\"d10\",\"state\":\"noise\",\"by\":\"op\"}"), 200);
    th = own("/api/frrs/history", "id=d10", 200);
    WT_HAS(th, "\"current\":{\"state\":\"noise\"");
    WT_EQ(route(&H, "/api/bundle", "kind=alert&id=d10"), 200);
    WT_ASSERT(section_is("alert", "triage", th, th ? strlen(th) : 0));
    free(th);
    WT_EQ(post("/api/frrs/triage", "{\"id\":\"d10\",\"state\":\"untriaged\"}"), 200);
}

/* kind=ble: the BLE drawer's own answer, /api/bundle?kind=ble splicing
 * /api/ble/{addr} (every sensor's row of the address), and the FRRS
 * record of the address and its first row's type. Under Local the
 * drawer is the router's out-of-scope note and no row is carried: seen
 * red with the bundle's local test made 0 (the rows came through). */
static void test_ble_bundle(void) {
    char *bd = own("/api/ble/" BLE_ADDR, "", 200);
    char *fr = own("/api/frrs/report", "kind=ble&addr=" BLE_ADDR "/0", 200);
    WT_EQ(route(&H, "/api/bundle", "kind=ble&id=02-DE-00-00-00-21"), 200);
    WT_HAS(answer(), "\"kind\":\"ble\",\"id\":\"" BLE_ADDR "\",");
    WT_ASSERT(section_is("ble", "drawer", bd, bd ? strlen(bd) : 0));
    WT_ASSERT(section_is("ble", "frrs", fr, fr ? strlen(fr) : 0));
    WT_HAS(bd, "\"name\":\"kettle\"");
    WT_HAS(answer(), "{\"what\":\"ble.frrs\",\"ms\":");
    /* ble_device is a poll type the ticker ring does not keep: no
     * records section to carry (seen red with a ble records_recent row
     * added to the registry). */
    WT_LACKS(answer(), "\"records_recent\":");
    free(bd); free(fr);
    size_t n = 0;

    WT_EQ(route(&H, "/api/bundle", "scope=local&kind=ble&id=" BLE_ADDR), 200);
    char oos[512];
    size_t ol = web_ble_out_of_scope_json(oos, sizeof(oos));
    WT_ASSERT(ol > 1);
    WT_ASSERT(section_is("ble", "drawer", oos, ol - 1));
    const char *b = top(answer(), "ble", &n);
    WT_ASSERT(b != NULL);
    if (b) {
        WT_LACKS(b, "\"rows\":");
        WT_LACKS(b, "kettle");
    }
    WT_HAS(answer(), "{\"field\":\"ble.drawer.rows, ble.drawer.alerts\",");
    WT_HAS(answer(), ",\"frrs\":{\"available\":false,\"reason\":\"withheld\"}");
}

/* kind=platform: the TACDB platform view's answer, as frrs.js's hook
 * asks for it (SlothFrrs.mountBundle on the platform view). A platform
 * is the operator's filing, not a device: no ticker records, no
 * sections. The records' absence seen red with a platform
 * records_recent row added to the registry. */
static void test_platform_bundle(void) {
    WT_ASSERT(g_frrs.wr != NULL);
    if (!g_frrs.wr) return;
    char sql[256];
    snprintf(sql, sizeof(sql), "INSERT INTO tacdb_platform (id,nomenclature,created,updated) "
             "VALUES (1,'KETTLE-1',%lld,%lld)", T - 60, T - 60);
    WT_EQ(sqlite3_exec(g_frrs.wr, sql, NULL, NULL, NULL), SQLITE_OK);
    char *pv = own("/api/frrs/tacdb/view", "id=1", 200);
    WT_EQ(route(&H, "/api/bundle", "kind=platform&id=1"), 200);
    WT_HAS(answer(), "\"kind\":\"platform\",\"id\":\"1\",");
    WT_ASSERT(section_is("platform", "view", pv, pv ? strlen(pv) : 0));
    WT_HAS(pv, "\"nomenclature\":\"KETTLE-1\"");
    size_t n = 0;
    const char *p = top(answer(), "platform", &n);
    WT_ASSERT(p && p[n - 1] == '}' && pv && n == strlen(pv) + strlen("{\"view\":") + 1);
    WT_LACKS(answer(), "\"records_recent\":");
    WT_HAS(answer(), "\"reads\":[{\"what\":\"platform\",\"ms\":");
    free(pv);
}

/* An alert that names an address and no MAC: the Lookup card of the
 * address rides in place of a drawer. */
static void test_alert_with_an_address_only(void) {
    WT_EQ(route(&H, "/api/alert", "id=d7"), 200);
    WT_HAS(body_of(g_out), "\"device\":{\"mac\":null,\"ip\":\"192.0.2.50\"}");
    WT_EQ(route(&H, "/api/bundle", "kind=alert&id=d7"), 200);
    const char *v = alert_page(answer());
    const char *after = v ? strstr(v, "\"history\":{") : NULL;
    WT_ASSERT(after != NULL);
    if (!after) return;
    WT_HAS(after, ",\"device\":{\"available\":false,\"reason\":\"no_data\"}");
    WT_HAS(after, ",\"lookup\":{\"q\":\"192.0.2.50\",\"kind\":\"ip\",");
    WT_HAS(answer(), "},{\"what\":\"alert.lookup\",\"ms\":");
    /* The observed values beside the trigger prose. */
    WT_HAS(after, ",\"observed_vs_thresholds\":{\"observed\":{\"sev\":1,\"count\":");
    WT_HAS(after, "\"thresholds\":{\"available\":false,\"reason\":\"not_built\",");
    WT_HAS(after, ",\"records_by_type_global\":{");
    /* A stream incident with a MAC in its key: the drawer, nested. */
    char q[64];
    snprintf(q, sizeof(q), "kind=alert&id=%s", S(IB));
    WT_EQ(route(&H, "/api/bundle", q), 200);
    v = alert_page(answer());
    after = v ? strstr(v, "\"history\":{") : NULL;
    WT_ASSERT(after != NULL);
    if (after) WT_HAS(after, ",\"device\":{\"mac\":\"02:00:00:00:00:12\",\"now\":");
    /* Copied from the page: the key is in sloth.db too, so count is
     * the larger source's and latest_count the stream incident's. */
    WT_HAS(answer(), "\"sev\":2,\"technique\":\"T1498.001\"");
    WT_HAS(answer(), "\"count\":40,\"latest_count\":6,\"observations\":0,");
    WT_HAS(answer(), "\"observed\":{\"sev\":2,\"count\":40,\"latest_count\":6,\"observations\":0,"
                     "\"incidents\":1,\"sev_changes\":3,\"duration_s\":7080,");
    WT_HAS(answer(), ",\"state\":\"closed\",\"reason\":\"expired\"}");
}

/* Every row of the registry is in its kind's section, with data or
 * marked unavailable with a reason from the fixed list, once. Seen red
 * with a row added to the table with no fill and a reason of its own
 * ("later"). */
static void test_every_section_is_present_or_marked(void) {
    static const struct { const char *kind, *query; } K[] = {
        { "device", "kind=device&id=02:00:00:00:00:12" },
        { "alert", "kind=alert&id=d10" },
        { "lookup", "kind=lookup&id=02:00:00:00:00:18" },
        { "ble", "kind=ble&id=" BLE_ADDR },
    };
    static const char *const primary[] = { "drawer", "page", "card", "drawer" };
    int rows = 0;
    for (size_t k = 0; k < sizeof(K) / sizeof(K[0]); k++) {
        WT_EQ(route(&H, "/api/bundle", K[k].query), 200);
        /* The kind's own primary: "page" alone finds the envelope's,
         * which walked the alert's sections from the envelope and
         * matched the page's own assessment and evidence members. */
        char pk[32];
        snprintf(pk, sizeof(pk), "\"%s\":{", K[k].kind);
        const char *v = member(strstr(answer(), pk), primary[k]);
        WT_ASSERT(v != NULL);
        if (!v) continue;
        /* Past the primary splice (its members are the route's): the
         * close of the object that starts at v, strings skipped. */
        const char *from = v;
        int depth = 0;
        for (const char *p = v; *p; p++) {
            if (*p == '"') {
                p++;
                while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
                if (!*p) break;
                continue;
            }
            if (*p == '{') depth++;
            if (*p == '}' && --depth == 0) { from = p + 1; break; }
        }
        const char *sect_end = strstr(from, ",\"glossary\":{");
        WT_ASSERT(sect_end != NULL);
        if (!sect_end) continue;
        for (size_t i = 0; i < web_bundle_sections_n; i++) {
            const web_bundle_sec_t *s = &web_bundle_sections[i];
            if (strcmp(s->kind, K[k].kind)) continue;
            rows++;
            char key[96];
            snprintf(key, sizeof(key), ",\"%s\":", s->name);
            const char *at = strstr(from, key);
            if (!at || at > sect_end) fprintf(stderr, "    %s: no %s\n", K[k].kind, s->name);
            WT_ASSERT(at && at < sect_end);
            if (!at) continue;
            const char *val = at + strlen(key);
            if (!strncmp(val, "{\"available\":false,\"reason\":\"", 29)) {
                char word[32] = "";
                sscanf(val + 29, "%31[a-z_]", word);
                int known = 0;
                for (size_t r = 0; r < web_bundle_reasons_n; r++)
                    if (!strcmp(word, web_bundle_reasons[r])) known = 1;
                if (!known) fprintf(stderr, "    %s.%s: reason %s\n", K[k].kind, s->name, word);
                WT_ASSERT(known);
                if (!s->fill) WT_ASSERT(!strcmp(word, s->reason));
            } else {
                WT_ASSERT(val[0] == '{' || val[0] == '[');
                WT_ASSERT(s->fill != NULL);
            }
        }
    }
    WT_EQ(rows, (int)web_bundle_sections_n);
    /* The reasons list is the documented one. */
    WT_EQ(web_bundle_reasons_n, 9);
    WT_ASSERT(!strcmp(web_bundle_reasons[0], "not_built") &&
              !strcmp(web_bundle_reasons[6], "not_kept") &&
              !strcmp(web_bundle_reasons[7], "read_error") &&
              !strcmp(web_bundle_reasons[8], "no_store"));
}

/* test_alerts.c's credential and incident-id tests, against the
 * bundle: the username-bearing key, the community in a withheld detail
 * and sloth's incident_ids are seeded in both sources, and no bundle
 * carries them, while "withheld" says what was left out. */
static void test_withheld_and_opaque_ids(void) {
    static const char *const ids[] = { IA, IB, IC };
    const char *qs[8] = {
        "kind=device&id=02:00:00:00:00:12", "kind=device&id=02:00:00:00:00:18",
        "kind=alert&id=d20", "kind=alert&id=d21", "kind=alert&id=d22",
        "kind=lookup&id=10.0.0.1", "kind=lookup&id=02:00:00:00:00:12", NULL,
    };
    char qc[64];
    snprintf(qc, sizeof(qc), "kind=alert&id=%s", S(IC));
    qs[7] = qc;
    for (size_t i = 0; i < 8; i++) {
        int st = route(&H, "/api/bundle", qs[i]);
        if (st != 200) fprintf(stderr, "    ?%s: %d\n", qs[i], st);
        WT_EQ(st, 200);
        const char *b = answer();
        if (strstr(b, "alice") || strstr(b, "community-secret") || strstr(b, "cred:"))
            fprintf(stderr, "    ?%s carries it\n", qs[i]);
        WT_LACKS(b, "alice");
        WT_LACKS(b, "community-secret");
        WT_LACKS(b, "cred:");
        WT_LACKS(b, "snmp-brute:");
        WT_LACKS(b, "\"key\":");
        WT_LACKS(b, "\"incident_id\":");
        for (int k = 0; k < 3; k++) {
            if (strstr(b, ids[k])) fprintf(stderr, "    ?%s carries %s\n", qs[i], ids[k]);
            WT_LACKS(b, ids[k]);
        }
        WT_HAS(b, "{\"field\":\"alert.key, alert.incident_id\",\"why\":\"opaque ids only:");
        WT_HAS(b, "{\"field\":\"sloth.db columns\",\"why\":\"credential-bearing columns");
        WT_HAS(b, "{\"field\":\"page.url\",\"why\":\"filled by the browser, not the server\"}");
    }
    /* Withheld, and said to be, on the credential's and the brute
     * force's pages. */
    WT_EQ(route(&H, "/api/bundle", "kind=alert&id=d22"), 200);
    WT_HAS(answer(), "\"detail\":null,\"detail_shown\":false");
    WT_HAS(answer(), "{\"field\":\"alert.page.detail\",\"why\":\"this alert type's detail is "
                     "not audited");
    WT_EQ(route(&H, "/api/bundle", qc), 200);
    WT_HAS(answer(), "\"detail\":null,\"detail_shown\":false");
    WT_HAS(answer(), "{\"field\":\"alert.page.detail\",");
    /* And not on a page whose detail is shown. */
    WT_EQ(route(&H, "/api/bundle", "kind=alert&id=d10"), 200);
    WT_HAS(answer(), "\"detail_shown\":true");
    /* Seen red with the entry written whatever detail_shown says. */
    WT_LACKS(answer(), "{\"field\":\"alert.page.detail\",");
}

/* The caps. A device whose address ten thousand records name gets the
 * ring's fifty, newest first, and "limits" says the ring was full.
 * Seen red with WEB_LIVE_RING and WEB_BUNDLE_RECORDS both raised to 60
 * (q9949 listed, 60 records). */
static void test_caps_are_proven(void) {
    char line[160];
    for (int i = 0; i < 10000; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"dns\",\"ts\":%lld,\"qname\":\"q%d.example.org\",\"src\":\"192.0.2.12\"}\n",
                 T - 5 + i / 2000, i);
        feed(line);
    }
    WT_EQ(route(&H, "/api/bundle", "kind=device&id=02:00:00:00:00:12"), 200);
    const char *b = answer();
    WT_HAS(b, "\"ring_records\":50,\"ring_full\":true,");
    WT_HAS(b, "\"matched\":50,\"by_type\":{\"dns\":50},\"records\":[");
    WT_EQ(count_of(b, "{\"seq\":"), 50);
    WT_HAS(b, "\"text\":\"q9999.example.org");
    WT_LACKS(b, "\"text\":\"q9949.example.org");
    WT_HAS(b, "{\"name\":\"device.records_recent\",\"cap\":50,\"cut\":true,\"ring_records\":50}");
    /* Newest first: the first record listed is the newest. */
    const char *r = strstr(b, "\"records\":[{\"seq\":");
    WT_ASSERT(r != NULL);
    if (r) WT_HAS(r, "\"text\":\"q9999.example.org");
    WT_ASSERT(g_body_len < (size_t)web_bundle_max);
    WT_HAS(b, "\"truncated_sections\":[]");
}

/* What the bundle holds back for the kind's optional rows' names and
 * markers (web_bundle.c). */
static size_t marker_reserve(const char *kind) {
    size_t n = 0;
    for (size_t i = 0; i < web_bundle_sections_n; i++)
        if (!strcmp(web_bundle_sections[i].kind, kind))
            n += strlen(web_bundle_sections[i].name) + 4 + WEB_BUNDLE_MARKER_MAX;
    return n;
}

/* The hard cap: optional sections that would cross it are rolled back
 * to too_large and named, the required part stands; a cap the required
 * part cannot meet is a 413. Seen red with the rollback's w->len
 * restore removed (a truncated member's bytes stayed). */
static void test_size_cap(void) {
    WT_EQ(route(&H, "/api/bundle", "kind=alert&id=d10"), 200);
    size_t full = g_body_len;
    char *page = NULL;
    const char *v = alert_page(answer());
    const char *pe = v ? strstr(v, "\"history\":{") : NULL;
    pe = pe ? strstr(pe, "}}") : NULL;
    if (v && pe) {
        page = malloc((size_t)(pe + 2 - v) + 1);
        if (page) { memcpy(page, v, (size_t)(pe + 2 - v)); page[pe + 2 - v] = '\0'; }
    }
    WT_ASSERT(page != NULL);
    /* Room for the page and every section before the nested drawer,
     * and 200 bytes of it: the glossary, the prompt and the limits'
     * reserve are held back, so the cap is measured from them. */
    const char *b = answer();
    /* The nested drawer, past the page (whose own "device" names it). */
    const char *dv = v && page ? strstr(v + strlen(page), ",\"device\":{\"mac\":") : NULL;
    const char *gl = strstr(b, ",\"glossary\":{");
    const char *li = strstr(b, ",\"limits\":{");
    WT_ASSERT(dv && gl && li && dv < gl && gl < li);
    if (!dv || !gl || !li) { free(page); return; }
    size_t capb = (size_t)(dv - b) + 200 + (size_t)(li - gl) + WEB_BUNDLE_LIMITS_MAX + 3 +
                  marker_reserve("alert");
    /* The drawer is longer than the 200 bytes left for it. */
    const char *dl = strstr(dv, "\"anomalies\":[");
    WT_ASSERT(dl && dl - dv > 400);
    web_bundle_max = capb;
    WT_EQ(route(&H, "/api/bundle", "kind=alert&id=d10"), 200);
    WT_ASSERT(g_body_len <= capb && g_body_len < full);
    WT_HAS(answer(), ",\"device\":{\"available\":false,\"reason\":\"too_large\",\"cap_bytes\":");
    /* The triage history after it (the FRRS slice's) has no room left
     * either, nor the location stamp after that. */
    WT_HAS(answer(), "\"truncated_sections\":[\"device\",\"triage\",\"location\"]");
    char cap[64];
    snprintf(cap, sizeof(cap), "\"limits\":{\"hard_cap_bytes\":%zu,", capb);
    WT_HAS(answer(), cap);
    v = alert_page(answer());
    if (page) WT_ASSERT(v && !strncmp(v, page, strlen(page)));
    WT_ASSERT(g_body_len >= 2 && !strcmp(answer() + g_body_len - 2, "}\n"));
    /* No room for the page: refused whole. */
    web_bundle_max = 4096;
    WT_EQ(route(&H, "/api/bundle", "kind=alert&id=d10"), 413);
    WT_HAS(answer(), "{\"error\":\"bundle_too_large\"}");
    web_bundle_max = WEB_BUNDLE_MAX;
    free(page);
}

/* A named scope is the first member, the sub-answers say in_scope, the
 * scope in effect is reported and the excluded lists named. */
static void test_scope_is_carried_through(void) {
    WT_EQ(route(&H, "/api/bundle", "scope=monitor&kind=device&id=02:00:00:00:00:12"), 200);
    const char *b = answer();
    WT_HAS(b, "{\"scope\":\"monitor\",\"bundle_schema\":");
    WT_HAS(b, ",\"scope_in_effect\":{\"scope\":\"monitor\",\"given\":true,");
    WT_HAS(b, "\"excludes\":\"everything the host\\u0027s own interfaces carried:");
    WT_HAS(b, "{\"field\":\"device.drawer.ips, device.drawer.stream,");
    WT_HAS(b, "\"ips\":[],\"ips_more\":false");
    WT_HAS(b, ",\"in_scope\":false}");          /* no monitor source on the row */
    WT_EQ(route(&H, "/api/bundle", "kind=alert&id=d10&scope=local"), 200);
    b = answer();
    WT_HAS(b, "{\"scope\":\"local\",\"bundle_schema\":");
    WT_HAS(b, "\"alert\":{\"page\":{\"id\":\"d10\",\"in_scope\":false,");
    WT_HAS(b, "{\"field\":\"device.drawer.ssids, device.drawer.assocs\",");
    /* An error names the scope too, as every route's does. */
    WT_EQ(route(&H, "/api/bundle", "scope=local&kind=device"), 400);
    WT_HAS(answer(), "{\"scope\":\"local\",\"error\":\"missing_id\"}");
    /* Hybrid, named: echoed, excluding nothing. */
    WT_EQ(route(&H, "/api/bundle", "scope=hybrid&kind=lookup&id=192.0.2.18"), 200);
    WT_HAS(answer(), "{\"scope\":\"hybrid\",\"bundle_schema\":");
    WT_HAS(answer(), "\"given\":true,");
    WT_HAS(answer(), "\"excludes\":\"nothing: every source\"");
}

/* ── the review's findings (2026-10-27) ────────────────────────────── */

/* The records section of a device bundle: from its member to the next
 * row's (vendor_research), so a name the drawer itself carries is not
 * mistaken for one the records carry. */
static char *records_of(const char *b) {
    const char *r = b ? strstr(b, ",\"records_recent\":{") : NULL;
    const char *e = r ? strstr(r, ",\"vendor_research\":") : NULL;
    if (!r || !e) return NULL;
    char *o = malloc((size_t)(e - r) + 1);
    if (o) { memcpy(o, r, (size_t)(e - r)); o[e - r] = '\0'; }
    return o;
}

/* The ticker records follow the scope as the page's ticker does: only
 * the scope's records, and under Monitor a device row's own line (its
 * MAC and SSID; no address, no name). A device row with an ARP and a
 * probe source is both scopes'; the DNS query is Local's, the probe
 * Monitor's. Seen red with the scope skip removed from rec_line() (the
 * probe under Local) and with r->text written in place of text_m (the
 * address and name under Monitor). The Local DNS line under Monitor is
 * asserted, not claimed: Monitor's drawer holds no address, so no key
 * matches it whatever the skip does. */
static void test_records_follow_the_scope(void) {
    char line[512];
    snprintf(line, sizeof(line),
             "{\"type\":\"device\",\"ts\":%lld,\"mac\":\"02:00:00:00:00:12\","
             "\"ip\":\"192.0.2.12\",\"hostname\":\"laptop-hn\",\"sources\":17,"
             "\"last_ssid\":\"HomeNet\"}\n", T - 6);
    feed(line);
    /* Hybrid: the device row's line has its address and name. */
    WT_EQ(route(&H, "/api/bundle", "kind=device&id=02:00:00:00:00:12"), 200);
    char *r = records_of(answer());
    WT_ASSERT(r != NULL);
    if (!r) return;
    WT_HAS(r, "\"type\":\"device\"");
    WT_HAS(r, "laptop-hn");
    WT_HAS(r, "laptop.example.org");
    WT_HAS(r, "\"text\":\"HomeNet  02:00:00:00:00:12\"");
    free(r);

    WT_EQ(route(&H, "/api/bundle", "scope=monitor&kind=device&id=02:00:00:00:00:12"), 200);
    r = records_of(answer());
    WT_ASSERT(r != NULL);
    if (!r) return;
    WT_HAS(r, "\"type\":\"device\"");
    WT_HAS(r, "\"text\":\"02:00:00:00:00:12  HomeNet\"");
    WT_HAS(r, "\"text\":\"HomeNet  02:00:00:00:00:12\"");
    WT_LACKS(r, "laptop-hn");
    WT_LACKS(r, "192.0.2.12");
    WT_LACKS(r, "laptop.example.org");
    WT_LACKS(r, "\"type\":\"dns\"");
    free(r);

    WT_EQ(route(&H, "/api/bundle", "scope=local&kind=device&id=02:00:00:00:00:12"), 200);
    r = records_of(answer());
    WT_ASSERT(r != NULL);
    if (!r) return;
    WT_HAS(r, "laptop.example.org");
    WT_HAS(r, "laptop-hn");
    WT_LACKS(r, "\"type\":\"probe_client\"");
    WT_LACKS(r, "HomeNet  02:00:00:00:00:12");
    free(r);
}

/* The ring record whose line contains marker, or NULL. */
static const web_live_rec_t *ring_rec(web_live_rec_t *buf, const char *marker) {
    unsigned long long latest = 0;
    int n = web_live_recent_after(g_live, 0, buf, WEB_LIVE_RING, &latest);
    for (int i = n - 1; i >= 0; i--)
        if (strstr(buf[i].text, marker)) return &buf[i];
    return NULL;
}

/* A record is matched on its address members, never on its line: the
 * line is cut at WEB_LIVE_TEXT_MAX, and a 68-byte query name puts
 * 192.0.2.123 at the cut as "192.0.2.12"; an SSID that reads
 * "192.0.2.12" names no host; 192.0.2.120 and .125 are not .12, and a
 * connection's "192.0.2.12:443" is. Seen red with rec_match() also
 * accepting strstr(line, key) (the .123 query, the SSID probe, .120
 * and .125 listed), and the Monitor case with web_live_rec_names()
 * ignoring monitor_line (a device row's address matched on its Monitor
 * line, which does not show it). */
static void test_records_match_whole_addresses(void) {
    /* 68 bytes: with the two-space gap and 192.0.2.123 the line is 81,
     * one past WEB_LIVE_TEXT_MAX, so the cut drops the 3. (67 is the
     * review's figure; that line is 80 and fits whole.) */
    char q68[69];
    memset(q68, 'q', 68);
    q68[68] = '\0';
    memcpy(q68 + 68 - 12, ".example.org", 12);
    char line[512];
    snprintf(line, sizeof(line),
        "{\"type\":\"dns\",\"ts\":1792627195,\"qname\":\"q120.example.org\","
        "\"src\":\"192.0.2.120\"}\n"
        "{\"type\":\"dns\",\"ts\":1792627196,\"qname\":\"q125.example.org\","
        "\"src\":\"192.0.2.125\"}\n"
        "{\"type\":\"dns\",\"ts\":1792627197,\"qname\":\"%s\",\"src\":\"192.0.2.123\"}\n"
        "{\"type\":\"probe_client\",\"ts\":1792627198,\"mac\":\"02:00:00:00:00:99\","
        "\"ssid\":\"192.0.2.12\"}\n"
        "{\"type\":\"connections\",\"ts\":1792627199,\"src\":\"192.0.2.12:443\","
        "\"dst\":\"[FE80::A]:22\",\"proto\":\"tcp\"}\n", q68);
    feed(line);
    web_live_rec_t buf[WEB_LIVE_RING];
    const web_live_rec_t *cut = ring_rec(buf, "qqqq");
    WT_ASSERT(cut != NULL);
    if (cut) {
        /* The fixture is the cut case: the line ends in the shorter key. */
        size_t n = strlen(cut->text);
        WT_ASSERT(n >= 10 && !strcmp(cut->text + n - 10, "192.0.2.12"));
        WT_ASSERT(!web_live_rec_names(cut, "192.0.2.12", 0));
        WT_ASSERT(web_live_rec_names(cut, "192.0.2.123", 0));
    }
    const web_live_rec_t *conn = ring_rec(buf, "192.0.2.12:443");
    WT_ASSERT(conn != NULL);
    if (conn) {
        WT_ASSERT(web_live_rec_names(conn, "192.0.2.12", 0));
        WT_ASSERT(web_live_rec_names(conn, "fe80::a", 0));
        WT_ASSERT(!web_live_rec_names(conn, "fe80::", 0));
    }
    WT_EQ(route(&H, "/api/bundle", "kind=device&id=02:00:00:00:00:12"), 200);
    char *r = records_of(answer());
    WT_ASSERT(r != NULL);
    if (!r) return;
    WT_HAS(r, "laptop.example.org");
    WT_HAS(r, "\"type\":\"connections\"");
    WT_LACKS(r, "q120.example.org");
    WT_LACKS(r, "q125.example.org");
    WT_LACKS(r, "qqqq");
    WT_LACKS(r, "\"type\":\"probe_client\",\"ts\":1792627198");
    free(r);
    /* Under Monitor a device row matches on its MAC alone. */
    snprintf(line, sizeof(line),
             "{\"type\":\"device\",\"ts\":%lld,\"mac\":\"02:00:00:00:00:12\","
             "\"ip\":\"192.0.2.12\",\"hostname\":\"mon-hn\",\"sources\":17,"
             "\"last_ssid\":\"HomeNet\"}\n", T - 5);
    feed(line);
    const web_live_rec_t *dev = ring_rec(buf, "mon-hn");
    WT_ASSERT(dev != NULL);
    if (dev) {
        WT_ASSERT(web_live_rec_names(dev, "02:00:00:00:00:12", 1));
        WT_ASSERT(web_live_rec_names(dev, "192.0.2.12", 0));
        WT_ASSERT(!web_live_rec_names(dev, "192.0.2.12", 1));
    }
}

/* sensor's counts are the scope's, as /api/live's under the same scope.
 * Seen red with scope_sum() left out of web_live_bundle_sensor() (the
 * whole sensor's two open warnings under Monitor). */
static void test_sensor_counts_follow_the_scope(void) {
    static const char *const sc[] = { "monitor", "local", "hybrid" };
    for (int i = 0; i < 3; i++) {
        char q[96];
        snprintf(q, sizeof(q), "scope=%s", sc[i]);
        WT_EQ(route(&H, "/api/live", q), 200);
        const char *live = body_of(g_out);
        const char *ao = strstr(live, "\"alerts_open\":{");
        const char *ae = ao ? strchr(ao, '}') : NULL;
        WT_ASSERT(ao && ae);
        if (!ao || !ae) return;
        char want[160];
        snprintf(want, sizeof(want), "%.*s", (int)(ae + 1 - ao), ao);
        snprintf(q, sizeof(q), "scope=%s&kind=device&id=02:00:00:00:00:12", sc[i]);
        WT_EQ(route(&H, "/api/bundle", q), 200);
        const char *sen = strstr(answer(), ",\"sensor\":{\"socket\":");
        WT_ASSERT(sen != NULL);
        if (sen) WT_HAS(sen, want);
        if (i == 0) WT_HAS(want, "\"warn\":0");     /* both warnings are Local's */
        if (i == 2) WT_HAS(want, "\"warn\":2");
    }
}

static void reason_is(int status, const char *body, const char *want) {
    const char *got = web_bundle_nested_reason(status, body);
    if (strcmp(got, want)) fprintf(stderr, "    ?%d %s: %s\n", status, body ? body : "-", got);
    WT_ASSERT(!strcmp(got, want));
}

/* A nested read that did not answer says why in its route's words. Seen
 * red with the old mapping (everything but no_sloth_db "budget"). */
static void test_nested_reasons(void) {
    reason_is(404, "{\"error\":\"no_such_device\"}", "no_data");
    reason_is(400, "{\"error\":\"bad_mac\"}", "no_data");
    reason_is(-1, NULL, "too_large");
    reason_is(-2, NULL, "read_error");
    reason_is(503, "{\"error\":\"no_sloth_db\",\"detail\":\"x\"}", "no_sloth_db");
    reason_is(503, "{\"error\":\"sloth_db_timeout\"}", "budget");
    reason_is(503, "{\"error\":\"sloth_db_error\"}", "read_error");
    /* The FRRS routes' own words. */
    reason_is(503, "{\"error\":\"no_store\"}", "no_store");
    reason_is(503, "{\"error\":\"record_too_large\"}", "too_large");
    reason_is(404, "{\"error\":\"no_such_alert\"}", "no_data");
    /* A detail naming another word does not decide it. */
    reason_is(503, "{\"error\":\"sloth_db_error\",\"detail\":\"no_sloth_db\"}", "read_error");
}

/* The glossary's risk is sloth's device_risk_level_t, 0..3, with the
 * thresholds of web_scope_risk_level() (the page's own clamp). */
static void test_glossary_risk_is_the_level(void) {
    WT_EQ(route(&H, "/api/bundle", "kind=device&id=02:00:00:00:00:12"), 200);
    WT_HAS(answer(), "\"risk\":\"sloth\\u0027s device risk level: 0 LOW, 1 MED, 2 HIGH, "
                     "3 CRIT, from the weighted sum of risk_signals (weights 1,1,1,1,3,3 in "
                     "bit order; \\u003e=1 MED, \\u003e=3 HIGH, \\u003e=5 CRIT)\"");
    WT_EQ(DEV_RISK_LOW, 0);
    WT_EQ(DEV_RISK_CRIT, 3);
    WT_EQ(web_scope_risk_level(1), 1);
    WT_EQ(web_scope_risk_level(1 | 2 | 4), 2);
    WT_EQ(web_scope_risk_level(16 | 1 | 2), 3);
}

/* count and observations are evaluations of a standing condition, not
 * frames or requests (src/alerts/engine.c: evaluations++ on every fire;
 * observations++ whenever detail_sig differs, and detail_sig is only
 * refreshed on a severity change or past the 60 s update floor), and
 * the prompt does not hand them to the analyst as event counts. Seen red
 * with the old "the underlying events the rule counted" entry restored. */
static void test_glossary_counts_are_evaluations(void) {
    WT_EQ(route(&H, "/api/bundle", "kind=alert&id=d10"), 200);
    const char *b = answer();
    WT_HAS(b, "\"count\":\"rule evaluations that fired while the condition held (about "
              "one per evaluation pass), across every incident of the key; not packets "
              "or requests; latest_count is the one incident this id names\"");
    WT_HAS(b, "\"observations\":\"evaluations at which the rendered detail or severity "
              "differed from the last emitted one (stream only); it follows evaluations "
              "while detail keeps changing inside the 60 s update floor; not a count of "
              "frames or requests\"");
    WT_HAS(b, "An alert\\u0027s count and observations are evaluations of a standing "
              "condition, not event counts");
    WT_LACKS(b, "the underlying events the rule counted");
    WT_LACKS(b, "the alert\\u0027s count/observations/severity history");
}

/* A stream summary that does not render is not an empty mix: "{}" would
 * read as "no records". Seen red with fill_types writing "{}" for an
 * unrendered summary again. The no-map-in-a-rendered-summary branch
 * cannot be isolated: web_live_json_scoped always writes "types". */
static void test_types_unrendered_is_not_empty(void) {
    WT_EQ(route(&H, "/api/bundle", "kind=alert&id=d10"), 200);
    WT_HAS(answer(), ",\"records_by_type_global\":{\"");
    WT_LACKS(answer(), ",\"records_by_type_global\":{\"available\":false");
    web_bundle_scratch = 64;
    WT_EQ(route(&H, "/api/bundle", "kind=alert&id=d10"), 200);
    web_bundle_scratch = WEB_BUNDLE_SCRATCH;
    WT_HAS(answer(), ",\"records_by_type_global\":{\"available\":false,"
                     "\"reason\":\"too_large\",");
    WT_LACKS(answer(), "\"records_by_type_global\":{}");
}

/* Every cap from the least the required part needs up: a 200 that ends
 * whole, or a 413 below the first 200; never a 413 above one, which is
 * a body that overflowed once the optional rows' markers were written
 * past the fills' budget. The markers (886 bytes for an alert) are
 * absorbed today by WEB_BUNDLE_LIMITS_MAX's slack (4096 held, 1061
 * written here), so leaving their reserve out alone stays green; seen
 * red with it left out and WEB_BUNDLE_LIMITS_MAX cut to 1200 (a 413
 * above a 200), and green with 1200 and the reserve in. */
static void test_markers_fit_under_every_cap(void) {
    WT_EQ(route(&H, "/api/bundle", "kind=alert&id=d10"), 200);
    const char *b = answer();
    const char *o = strstr(b, ",\"observed_vs_thresholds\":");
    const char *gl = strstr(b, ",\"glossary\":{");
    const char *li = strstr(b, ",\"limits\":{");
    WT_ASSERT(o && gl && li);
    if (!o || !gl || !li) return;
    size_t lo = (size_t)(o - b) + (size_t)(li - gl) + WEB_BUNDLE_LIMITS_MAX;
    size_t hi = lo + marker_reserve("alert") + 512;
    int seen200 = 0, bad = 0;
    for (size_t cap = lo; cap <= hi; cap += 8) {
        web_bundle_max = cap;
        int st = route(&H, "/api/bundle", "kind=alert&id=d10");
        if (st == 200) {
            seen200 = 1;
            if (g_body_len > cap || g_body_len < 2 || strcmp(answer() + g_body_len - 2, "}\n"))
                bad++;
        } else if (st != 413 || seen200) {
            if (!bad) fprintf(stderr, "    cap %zu: %d %s\n", cap, st, answer());
            bad++;
        }
    }
    web_bundle_max = WEB_BUNDLE_MAX;
    WT_EQ(bad, 0);
    WT_ASSERT(seen200);
}


void run_bundle_tests(void) {
    WT_RUN(test_page_carries_the_control);
    WT_RUN(test_rawn_has_one_caller);
    up();
    WT_RUN(test_parameters_refused_whole);
    WT_RUN(test_device_bundle_shape);
    WT_RUN(test_spliced_answers_are_byte_identical);
    WT_RUN(test_alert_with_an_address_only);
    WT_RUN(test_every_section_is_present_or_marked);
    WT_RUN(test_withheld_and_opaque_ids);
    WT_RUN(test_scope_is_carried_through);
    WT_RUN(test_size_cap);
    WT_RUN(test_caps_are_proven);
    WT_RUN(test_sections_are_the_routes_bytes);
    WT_RUN(test_ble_bundle);
    WT_RUN(test_platform_bundle);
    down();
    up();
    WT_RUN(test_records_follow_the_scope);
    WT_RUN(test_records_match_whole_addresses);
    WT_RUN(test_sensor_counts_follow_the_scope);
    WT_RUN(test_nested_reasons);
    WT_RUN(test_glossary_risk_is_the_level);
    WT_RUN(test_glossary_counts_are_evaluations);
    WT_RUN(test_types_unrendered_is_not_empty);
    WT_RUN(test_markers_fit_under_every_cap);
    down();
}

#endif
