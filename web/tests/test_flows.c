/* The Flows routes (#164, M6; web_flows.h) through the route table,
 * without a socket, over a sloth.db generated from sloth's own DDL
 * (sdb_gen.c) on the pinned clock SDB_NOW: one tab's rows with their
 * validation and paging, an SMB1 session marked, the chord diagram's
 * pairs with the fold stated, and the columns that are never read
 * (an RDP cookie, an MQTT username, an SSH banner, the SNMP community
 * count, Kerberos' preauth counts). And the page's Flows view. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_assets.h"
#include "web_flows.h"
#include "web_routes.h"
#include "web_slothdb.h"
#include "wtest.h"
#include "wt_tmp.h"

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

/* Both routes need sloth.db, in every build. */
static void test_without_sloth_db(void) {
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T;
    WT_EQ(route(&h, "/api/flows", "proto=ssh"), 503);
    WT_HAS(body_of(g_out), "{\"error\":\"no_sloth_db\"");
    WT_EQ(route(&h, "/api/flows/graph", ""), 503);
    WT_HAS(body_of(g_out), "{\"error\":\"no_sloth_db\"");
}

/* Every column a tab names is on the allow-list, and none of the
 * columns the tabs leave out is. The second half seen red with
 * { "rdp_flows", "last_cookie" } added to web_sdb_allow[]. */
static int allowed(const char *table, const char *col) {
    for (size_t i = 0; i < web_sdb_allow_n; i++)
        if (!strcmp(web_sdb_allow[i].table, table) &&
            !strcmp(web_sdb_allow[i].column, col))
            return 1;
    return 0;
}

static void test_tabs_against_the_allow_list(void) {
    for (int k = 0; k < WEB_FP_KINDS; k++) {
        const web_sdb_ftab_t *t = &web_sdb_ftab[k];
        WT_EQ(web_sdb_ftab_find(t->name), k);
        WT_ASSERT(allowed(t->table, t->src));
        if (t->dst) WT_ASSERT(allowed(t->table, t->dst));
        for (int i = 0; t->cols[i]; i++) {
            if (!allowed(t->table, t->cols[i]))
                fprintf(stderr, "    %s.%s is not on the allow-list\n", t->table,
                        t->cols[i]);
            WT_ASSERT(allowed(t->table, t->cols[i]));
        }
        if (t->xint) WT_ASSERT(allowed(t->table, t->xint));
        if (t->xtext) WT_ASSERT(allowed(t->table, t->xtext));
        WT_ASSERT(allowed(t->table, "first_seen") && allowed(t->table, "last_seen"));
    }
    static const char *const off[][2] = {
        { "ssh_flows", "server_banner" }, { "rdp_flows", "last_cookie" },
        { "snmp_flows", "community_count" },
        { "kerb_events", "preauth_required_count" },
        { "kerb_events", "preauth_failed_count" },
        { "mqtt_flows", "src_ip" }, { "mqtt_flows", "last_username" },
    };
    for (size_t i = 0; i < sizeof(off) / sizeof(off[0]); i++) {
        if (allowed(off[i][0], off[i][1]))
            fprintf(stderr, "    %s.%s is on the allow-list\n", off[i][0], off[i][1]);
        WT_ASSERT(!allowed(off[i][0], off[i][1]));
    }
    WT_EQ(web_sdb_ftab_find("mqtt"), -1);
    WT_EQ(web_sdb_ftab_find("SSH"), -1);
}

/* The page's Flows view. Seen red with f-chord renamed in index.html
 * and with the "7" key case removed from app.js. The replaceState
 * line held to its window.history spelling: seen red on e89e3c2, where
 * it read "history.replaceState" and a local function hid the global. */
static void test_page_carries_the_flows_view(void) {
    const char *p = (const char *)web_page;
    static const char *const ids[] = {
        "v-flows", "nav-flows", "f-tabs", "f-note", "f-head", "f-rows",
        "f-count", "f-more", "f-chord", "f-fold", "f-legend", "f-win",
        "f-sort", "f-ip",
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
    WT_HAS(p, "getJSON(\"/api/flows?proto=\" + encodeURIComponent(F.proto)");
    WT_HAS(p, "getJSON(\"/api/flows/graph?from=\" + r.from + \"&to=\" + r.to");
    WT_HAS(p, "if (e.key === \"7\") show(\"flows\");");
    /* An SMB1 row is drawn in the critical colour, by a fixed class. */
    WT_HAS(p, "f.smb1 === true ? \"frow sev2\" : \"frow\"");
    WT_HAS(p, ".frow.sev2");
    /* The polish pass: the view list is buttons in tab order, wide
     * tables scroll in their own box, the page is dark whatever the
     * browser prefers, the address names the view, and a memory-only
     * build says why it has no sloth.db. */
    WT_HAS(p, "<button type=\"button\" class=\"go\" id=\"nav-flows\">");
    WT_HAS(p, ".hscroll { overflow-x: auto; max-width: 100%; }");
    WT_HAS(p, "color-scheme: dark;");
    WT_HAS(p, "<meta name=\"color-scheme\" content=\"dark\">");
    WT_HAS(p, "window.history.replaceState(null, \"\", \"#\" + v)");
    WT_HAS(p, "NOSQL = h.store === \"memory\";");
}

/* The page's script runs inside one function, where a declaration
 * named after a browser global hides it from every line of that
 * function: M6 shipped a "function history()" (the History view's
 * loader), so "history.replaceState" called it, threw, and the catch
 * around it hid that the address never named the view. No declaration
 * in the page may take the name of a global the page uses. Seen red
 * with historyView renamed back to history. */
static void test_page_shadows_no_browser_global(void) {
    const char *p = (const char *)web_page;
    static const char *const globals[] = {
        "window", "document", "location", "history", "navigator", "fetch",
        "setTimeout", "clearTimeout", "setInterval", "clearInterval",
        "getComputedStyle", "encodeURIComponent", "devicePixelRatio",
        "requestAnimationFrame", "EventSource", "URL", "JSON", "Math", "Date",
    };
    static const char *const forms[] = {
        "function %s(", "function %s (", "var %s ", "var %s=", "var %s;",
        "var %s,", "let %s ", "const %s ",
    };
    for (size_t g = 0; g < sizeof(globals) / sizeof(globals[0]); g++) {
        for (size_t f = 0; f < sizeof(forms) / sizeof(forms[0]); f++) {
            char decl[64];
            snprintf(decl, sizeof(decl), forms[f], globals[g]);
            if (strstr(p, decl)) fprintf(stderr, "    the page declares \"%s\"\n", decl);
            WT_ASSERT(strstr(p, decl) == NULL);
        }
    }
    /* The positive control: the page does use the globals checked. */
    WT_HAS(p, "window.history.");
    WT_HAS(p, "location.hash");
}

#ifndef WITH_SQLITE

void run_flows_tests(void) {
    WT_RUN(test_without_sloth_db);
    WT_RUN(test_tabs_against_the_allow_list);
    WT_RUN(test_page_carries_the_flows_view);
    WT_RUN(test_page_shadows_no_browser_global);
}

#else

static char g_dir[TEST_TMP_MAX];
static char g_db[128];
static web_slothdb_t sdb;
static web_m4_t m4;
static web_health_t H;

/* Every flow table, a pair or source in each, all inside the last
 * day; a second SMB session in SMB2; and the values that must never
 * be served: an RDP cookie, an SSH banner, an MQTT username, the SNMP
 * community count (31337) and Kerberos' preauth counts (4242, 4243). */
static int seed(void) {
    char sql[6000];
    long long a = T - 2 * HR, b = T - HR;
    int n = snprintf(sql, sizeof(sql),
        "INSERT INTO ssh_flows (src_ip,dst_ip,banner_count,server_banner,first_seen,"
        "last_seen) VALUES ('10.0.0.1','10.0.0.2',3,'SSH-2.0-banner',%lld,%lld);"
        "INSERT INTO rdp_flows (src_ip,dst_ip,connect_req_count,last_cookie,"
        "proto_mask,first_seen,last_seen) VALUES ('10.0.0.3','10.0.0.4',2,"
        "'mstshash=dave-secret',3,%lld,%lld);"
        "INSERT INTO smb_sessions (client_ip,server_ip,server_port,dialect,obs_count,"
        "first_seen,last_seen) VALUES ('10.0.0.5','10.0.0.6',445,'SMB1',7,%lld,%lld),"
        " ('10.0.0.5','10.0.0.11',445,'SMB2',1,%lld,%lld);"
        "INSERT INTO snmp_flows (src_ip,dst_ip,get_count,getnext_count,set_count,"
        "version,community_count,first_seen,last_seen) VALUES"
        " ('10.0.0.7','10.0.0.8',1,2,3,1,31337,%lld,%lld);"
        "INSERT INTO bgp_sessions (peer_a,peer_b,open_count,update_count,"
        "notification_count,keepalive_count,first_seen,last_seen) VALUES"
        " ('192.0.2.1','192.0.2.2',1,10,0,9,%lld,%lld);"
        "INSERT INTO ldap_events (src_ip,bind_count,bind_anon_count,search_count,"
        "search_ref_count,first_seen,last_seen) VALUES ('10.0.0.12',2,1,5,0,%lld,%lld);"
        "INSERT INTO kerb_events (src_ip,as_req_count,as_rep_count,tgs_req_count,"
        "tgs_rep_count,preauth_required_count,preauth_failed_count,"
        "principal_unknown_count,error_other_count,first_seen,last_seen) VALUES"
        " ('10.0.0.13',4,3,2,1,4242,4243,1,0,%lld,%lld);"
        "INSERT INTO mqtt_flows (src_ip,dst_ip,connect_count,last_username,"
        "first_seen,last_seen) VALUES ('10.0.0.9','10.0.0.10',1,'erin-secret',%lld,%lld);",
        a, b, a, b, a, b, a - 10, b - 10, a, b, a, b, a, b, a, b, a, b);
    if (n < 0 || (size_t)n >= sizeof(sql)) return -1;
    return sdb_exec(g_db, sql);
}

static void up(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-flows-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, db_schema_version(), 0), 0);
    WT_EQ(seed(), 0);
    web_slothdb_init(&sdb, g_db, NULL);
    memset(&m4, 0, sizeof(m4));
    m4.sdb = &sdb;
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.m4 = &m4;
}

static void down(void) {
    web_slothdb_destroy(&sdb);
    unlink(g_db);
    rmdir(g_dir);
}

static void lacks_secrets(const char *b) {
    WT_LACKS(b, "dave-secret");
    WT_LACKS(b, "mstshash");
    WT_LACKS(b, "erin-secret");
    WT_LACKS(b, "10.0.0.9");
    WT_LACKS(b, "SSH-2.0");
    WT_LACKS(b, "31337");
    WT_LACKS(b, "4242");
    WT_LACKS(b, "4243");
}

/* Each tab's rows as the route writes them, and no withheld value in
 * any tab's body. Each value is held out by two guards (the tab does
 * not name the column, and the allow-list would refuse it if it did)
 * or three (and the withheld list the authorizer checks too: the
 * cookie, the community count, the MQTT username), so no single mutant
 * reaches a body; each was seen red with all of its guards changed
 * together: kerb's preauth_failed_count (4243) and
 * preauth_required_count (4242) added to the tab and the list; ssh's
 * server_banner as its xtext and on the list (SSH-2.0); rdp's
 * last_cookie the same with the withheld check off (mstshash); snmp's
 * community_count as a counter, on the list, the check off (31337);
 * mqtt_flows in place of bgp_sessions with its columns listed (10.0.0.9)
 * and last_username as its xtext with the check off (erin-secret). */
static void test_tabs(void) {
    char want[512];
    WT_EQ(route(&H, "/api/flows", "proto=smb"), 200);
    const char *b = body_of(g_out);
    snprintf(want, sizeof(want), "{\"proto\":\"smb\",\"table\":\"smb_sessions\",\"from\":%lld,"
             "\"to\":%lld,\"ip\":null,\"sort\":\"last\",\"limit\":50,\"offset\":0,"
             "\"per_source\":false,\"columns\":[\"obs_count\"],\"withheld\":null,\"rows\":[",
             T - 30 * DY, T);
    WT_HAS(b, want);
    snprintf(want, sizeof(want), "{\"src\":\"10.0.0.5\",\"dst\":\"10.0.0.6\",\"counts\":[7],"
             "\"total\":7,\"server_port\":445,\"dialect\":\"SMB1\",\"smb1\":true,"
             "\"first_seen\":%lld,\"last_seen\":%lld}", T - 2 * HR, T - HR);
    WT_HAS(b, want);
    WT_HAS(b, "\"dialect\":\"SMB2\",\"smb1\":false,");
    WT_HAS(b, "],\"present\":true,\"count\":2,\"total\":2,\"more\":false}");
    /* Newest first: the SMB1 session ends 10 s after the other. */
    WT_ASSERT(strstr(b, "\"dst\":\"10.0.0.6\"") < strstr(b, "\"dst\":\"10.0.0.11\""));

    WT_EQ(route(&H, "/api/flows", "proto=kerb"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"per_source\":true,\"columns\":[\"as_req_count\",\"as_rep_count\","
              "\"tgs_req_count\",\"tgs_rep_count\",\"principal_unknown_count\","
              "\"error_other_count\"],\"withheld\":\"preauth_required_count and "
              "preauth_failed_count");
    WT_HAS(b, "{\"src\":\"10.0.0.13\",\"dst\":null,\"counts\":[4,3,2,1,1,0],\"total\":11,");
    lacks_secrets(b);

    WT_EQ(route(&H, "/api/flows", "proto=rdp"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"withheld\":\"last_cookie");
    WT_HAS(b, "{\"src\":\"10.0.0.3\",\"dst\":\"10.0.0.4\",\"counts\":[2],\"total\":2,"
              "\"proto_mask\":3,");
    lacks_secrets(b);
    WT_EQ(route(&H, "/api/flows", "proto=ssh"), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"src\":\"10.0.0.1\",\"dst\":\"10.0.0.2\",\"counts\":[3],\"total\":3,\"first_seen\":");
    lacks_secrets(b);
    WT_EQ(route(&H, "/api/flows", "proto=snmp"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"counts\":[1,2,0,3,0,0],\"total\":6,\"version\":1,");
    lacks_secrets(b);
    WT_EQ(route(&H, "/api/flows", "proto=ldap"), 200);
    WT_HAS(body_of(g_out), "{\"src\":\"10.0.0.12\",\"dst\":null,\"counts\":[2,1,5,0],\"total\":8,");
    lacks_secrets(body_of(g_out));
    WT_EQ(route(&H, "/api/flows", "proto=bgp"), 200);
    WT_HAS(body_of(g_out), "{\"src\":\"192.0.2.1\",\"dst\":\"192.0.2.2\",\"counts\":[1,10,0,9],"
                           "\"total\":20,");
    lacks_secrets(body_of(g_out));
    WT_EQ(route(&H, "/api/flows", "proto=smb"), 200);
    lacks_secrets(body_of(g_out));
}

/* Validation: every parameter whole, or a 400 with its reason. */
static void test_validation(void) {
    static const char *const bad[][2] = {
        { "", "missing_proto" }, { "proto=", "empty_value" },
        { "proto=mqtt", "proto_withheld" }, { "proto=SSH", "unknown_proto" },
        { "proto=ftp", "unknown_proto" }, { "proto=ssh&ip=10.0.0", "bad_ip" },
        { "proto=ssh&ip=example.org", "bad_ip" }, { "proto=ssh&sort=size", "bad_sort" },
        { "proto=ssh&limit=0", "bad_limit" }, { "proto=ssh&limit=201", "bad_limit" },
        { "proto=ssh&limit=1x", "bad_limit" }, { "proto=ssh&offset=-1", "bad_offset" },
        { "proto=ssh&offset=1000001", "bad_offset" }, { "proto=ssh&from=x", "bad_from" },
        { "proto=ssh&from=10&to=5", "empty_range" }, { "proto=ssh&to=1792900000", "to_in_future" },
        { "proto=ssh&from=1&to=1792627200", "range_too_long" },
        { "proto=ssh&proto=rdp", "repeated_parameter" }, { "proto=ssh&q=1", "unknown_parameter" },
    };
    char want[96];
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int st = route(&H, "/api/flows", bad[i][0]);
        snprintf(want, sizeof(want), "{\"error\":\"%s\"", bad[i][1]);
        if (st != 400 || !strstr(body_of(g_out), want))
            fprintf(stderr, "    %s -> %d %s\n", bad[i][0], st, body_of(g_out));
        WT_EQ(st, 400);
        WT_HAS(body_of(g_out), want);
    }
    WT_HAS(route(&H, "/api/flows", "proto=mqtt") == 400 ? body_of(g_out) : "",
           "\"detail\":\"mqtt_flows holds MQTT usernames; slothweb never reads that table\"");
    static const char *const gbad[][2] = {
        { "nodes=1", "bad_nodes" }, { "nodes=65", "bad_nodes" }, { "edges=0", "bad_edges" },
        { "edges=201", "bad_edges" }, { "from=x", "bad_from" }, { "proto=ssh", "unknown_parameter" },
    };
    for (size_t i = 0; i < sizeof(gbad) / sizeof(gbad[0]); i++) {
        WT_EQ(route(&H, "/api/flows/graph", gbad[i][0]), 400);
        snprintf(want, sizeof(want), "{\"error\":\"%s\"", gbad[i][1]);
        WT_HAS(body_of(g_out), want);
    }
}

/* Paging, sorting and the ip filter. A page of one leaves the second
 * row out: seen red with web_sdb_flows() binding 1000 for its limit. */
static void test_paging(void) {
    WT_EQ(route(&H, "/api/flows", "proto=smb&limit=1"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"dst\":\"10.0.0.6\"");
    WT_LACKS(b, "\"dst\":\"10.0.0.11\"");
    WT_HAS(b, "\"count\":1,\"total\":2,\"more\":true}");
    WT_EQ(route(&H, "/api/flows", "proto=smb&limit=1&offset=1"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"dst\":\"10.0.0.11\"");
    WT_HAS(b, "\"count\":1,\"total\":2,\"more\":false}");
    WT_EQ(route(&H, "/api/flows", "proto=smb&offset=5"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[],\"present\":true,\"count\":0,\"total\":2,\"more\":false}");
    /* sort=src: 10.0.0.5 -> 10.0.0.11 sorts before -> 10.0.0.6 as text. */
    WT_EQ(route(&H, "/api/flows", "proto=smb&sort=src"), 200);
    b = body_of(g_out);
    WT_ASSERT(strstr(b, "\"dst\":\"10.0.0.11\"") < strstr(b, "\"dst\":\"10.0.0.6\""));
    WT_EQ(route(&H, "/api/flows", "proto=smb&sort=total"), 200);
    b = body_of(g_out);
    WT_ASSERT(strstr(b, "\"dst\":\"10.0.0.6\"") < strstr(b, "\"dst\":\"10.0.0.11\""));
    /* ip matches either end. */
    WT_EQ(route(&H, "/api/flows", "proto=smb&ip=10.0.0.11"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"ip\":\"10.0.0.11\"");
    WT_HAS(b, "\"count\":1,\"total\":1,\"more\":false}");
    WT_EQ(route(&H, "/api/flows", "proto=smb&ip=10.0.0.5"), 200);
    WT_HAS(body_of(g_out), "\"count\":2,\"total\":2,");
    WT_EQ(route(&H, "/api/flows", "proto=ldap&ip=10.0.0.12"), 200);
    WT_HAS(body_of(g_out), "\"count\":1,\"total\":1,");
    /* A range before every row: none. */
    char q[128];
    snprintf(q, sizeof(q), "proto=smb&from=%lld&to=%lld", T - 10 * DY, T - 9 * DY);
    WT_EQ(route(&H, "/api/flows", q), 200);
    WT_HAS(body_of(g_out), "\"rows\":[],\"present\":true,\"count\":0,\"total\":0,");
}

/* The chord diagram's pairs: ldap and kerb are per-source and never
 * pairs (seen red with the pairs statement's "d <> ''" removed: 10.0.0.12
 * and 10.0.0.13 drawn); the fold says what was left out, and a node
 * folded is not listed (seen red with every node kept: 10.0.0.7). */
static void test_graph(void) {
    WT_EQ(route(&H, "/api/flows/graph", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"nodes\":[{\"id\":\"192.0.2.1\",\"total\":20},{\"id\":\"192.0.2.2\",\"total\":20},"
              "{\"id\":\"10.0.0.5\",\"total\":8},{\"id\":\"10.0.0.6\",\"total\":7},");
    WT_HAS(b, "\"edges\":[{\"s\":0,\"d\":1,\"proto\":\"bgp\",\"total\":20},"
              "{\"s\":2,\"d\":3,\"proto\":\"smb\",\"total\":7,\"smb1\":true},");
    WT_HAS(b, "\"fold\":{\"pairs\":6,\"pairs_shown\":6,\"pairs_folded\":0,\"flows\":39,"
              "\"flows_shown\":39,\"flows_folded\":0,\"nodes\":11,\"nodes_shown\":11,"
              "\"nodes_folded\":0}");
    WT_HAS(b, "\"tabs\":{\"ssh\":{\"rows\":1,\"total\":3},\"rdp\":{\"rows\":1,\"total\":2},"
              "\"smb\":{\"rows\":2,\"total\":8},\"snmp\":{\"rows\":1,\"total\":6},"
              "\"ldap\":{\"rows\":1,\"total\":8},\"kerb\":{\"rows\":1,\"total\":11},"
              "\"bgp\":{\"rows\":1,\"total\":20},\"mqtt\":\"withheld\"}}");
    WT_LACKS(b, "10.0.0.12");
    WT_LACKS(b, "10.0.0.13");
    lacks_secrets(b);
    /* Four nodes: the two pairs between them shown, the rest folded. */
    WT_EQ(route(&H, "/api/flows/graph", "nodes=4"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"edges\":[{\"s\":0,\"d\":1,\"proto\":\"bgp\",\"total\":20},"
              "{\"s\":2,\"d\":3,\"proto\":\"smb\",\"total\":7,\"smb1\":true}],");
    WT_HAS(b, "\"fold\":{\"pairs\":6,\"pairs_shown\":2,\"pairs_folded\":4,\"flows\":39,"
              "\"flows_shown\":27,\"flows_folded\":12,\"nodes\":11,\"nodes_shown\":4,"
              "\"nodes_folded\":7}");
    WT_LACKS(b, "10.0.0.7");
    /* One edge read: its two ends, every other pair folded. */
    WT_EQ(route(&H, "/api/flows/graph", "edges=1"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"nodes\":[{\"id\":\"192.0.2.1\",\"total\":20},{\"id\":\"192.0.2.2\",\"total\":20}],");
    WT_HAS(b, "\"fold\":{\"pairs\":6,\"pairs_shown\":1,\"pairs_folded\":5,\"flows\":39,"
              "\"flows_shown\":20,\"flows_folded\":19,\"nodes\":11,\"nodes_shown\":2,"
              "\"nodes_folded\":9}");
    /* A range with nothing in it. */
    char q[96];
    snprintf(q, sizeof(q), "from=%lld&to=%lld", T - 10 * DY, T - 9 * DY);
    WT_EQ(route(&H, "/api/flows/graph", q), 200);
    WT_HAS(body_of(g_out), "\"nodes\":[],\"edges\":[],\"fold\":{\"pairs\":0,");
}

/* A file without a table: that tab is absent, the others read. */
static void test_missing_table(void) {
    WT_EQ(sdb_exec(g_db, "DROP TABLE bgp_sessions"), 0);
    WT_EQ(route(&H, "/api/flows", "proto=bgp"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[],\"present\":false,\"count\":0,\"total\":0,\"more\":false}");
    WT_EQ(route(&H, "/api/flows/graph", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"bgp\":null,\"mqtt\":\"withheld\"}}");
    WT_HAS(b, "\"fold\":{\"pairs\":5,\"pairs_shown\":5,\"pairs_folded\":0,\"flows\":19,");
}

/* A page that would not fit its buffer stops early with "more", and
 * the next page starts where it stopped: 200 rows whose src escapes to
 * six bytes a character cannot all fit 64 KB. The text is escaped:
 * seen red with flow_json() writing src raw. */
static void test_page_that_does_not_fit(void) {
    char *sql = malloc(200 * 200 + 256);
    WT_ASSERT(sql != NULL);
    if (!sql) return;
    size_t o = (size_t)sprintf(sql, "INSERT INTO ldap_events (src_ip,bind_count,"
                               "first_seen,last_seen) VALUES ");
    for (int i = 0; i < 200; i++) {
        char src[64];
        memset(src, '<', 60);
        snprintf(src + 60, sizeof(src) - 60, "%03d", i);
        o += (size_t)sprintf(sql + o, "%s('%s',1,%lld,%lld)", i ? "," : "", src,
                             T - HR, T - 60);
    }
    WT_EQ(sdb_exec(g_db, sql), 0);
    free(sql);
    WT_EQ(route(&H, "/api/flows", "proto=ldap&limit=200&sort=src"), 200);
    const char *b = body_of(g_out);
    const char *c = strstr(b, "],\"present\":true,\"count\":");
    WT_ASSERT(c != NULL);
    int n = c ? atoi(c + strlen("],\"present\":true,\"count\":")) : 0;
    WT_ASSERT(n > 10 && n < 200);
    WT_HAS(b, "\"total\":201,\"more\":true}");
    WT_LACKS(b, "<");
    char q[64];
    snprintf(q, sizeof(q), "proto=ldap&limit=200&sort=src&offset=%d", n);
    WT_EQ(route(&H, "/api/flows", q), 200);
    char want[32];
    snprintf(want, sizeof(want), "%03d\"", n - 1);
    WT_HAS(body_of(g_out), want);
}

void run_flows_tests(void) {
    WT_RUN(test_without_sloth_db);
    WT_RUN(test_tabs_against_the_allow_list);
    WT_RUN(test_page_carries_the_flows_view);
    WT_RUN(test_page_shadows_no_browser_global);
    up();
    WT_RUN(test_tabs);
    WT_RUN(test_validation);
    WT_RUN(test_paging);
    WT_RUN(test_graph);
    WT_RUN(test_page_that_does_not_fit);
    WT_RUN(test_missing_table);
    down();
}

#endif
