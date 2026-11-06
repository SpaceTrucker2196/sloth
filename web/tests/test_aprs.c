/* The APRS panel (web_aprs.h) and its history (web_aprshist.h): the
 * stations kept by slothweb from hand-built records in the emitter's
 * exact shape (src/jsonl.c emit_aprs_packet(), emit_aprs_station() and
 * the aprs_* block of jsonl_emit_sensor_health(); tests/test_aprs.c pins
 * those), the routes through the route table under each scope, the
 * health member, and the two sloth.db routes over a file built from
 * sloth's own DDL (sdb_gen.c) with rows in the --db writer's shape
 * (src/db.c write_aprs(); tests/test_db.c pins it). Callsigns (N0TEST-n,
 * N0CALL-n) and positions are invented (docs/wiki/aprs.md, Privacy).
 *
 * Absence assertions, each seen red under a named mutation and restored:
 * the Local answer with route_aprs()'s none_here forced to 0 (a Local
 * answer carried stations); the range checks with packet_apply()'s
 * speed bound widened to 1e6 (the 5000 kt landed on the row); the
 * object rule with packet_apply()'s ';' / ')' return removed (the
 * sender took the object's position); the gone keep with age_out()'s
 * gone branch removed (the gone station stayed past its TTL); the
 * budget with the list's WEB_APRS_ROW_WORST check removed (the answer
 * overflowed and the route went 503); the history window with
 * web_sdb_aprs_seen()'s "last_seen >= ?1" dropped (the 9-day-old
 * station came back in a 7-day answer); the Local history answer with
 * route_m5()'s RF_APRS_* none_here branch removed; the q refusal with
 * '%' and '_' admitted by q_take(). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_aprs.h"
#include "web_aprshist.h"
#include "web_assets.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_routes.h"
#include "web_scope.h"
#include "wtest.h"
#include "wt_tmp.h"

#define T 1793930100LL

static web_aprs_t A;
static web_jrec_t R;

static void feed(const char *line) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_aprs_record(&A, &R, 1000);
}

static const char SH[] =
    "{\"type\":\"sensor_health\",\"ts\":1793930100,\"capture_iface\":\"any\","
    "\"aprs_state\":\"live\",\"aprs_src\":\"file:/var/lib/direwolf/aprs.log\","
    "\"aprs_missing\":0,\"aprs_last_read\":1793930099,\"aprs_last_packet\":1793930060,"
    "\"aprs_stations\":2,\"aprs_bytes\":4096,\"aprs_lines\":12,\"aprs_packets\":11,"
    "\"aprs_bad_lines\":1,\"aprs_overflow\":0,\"aprs_expired\":3,\"aprs_truncations\":1,"
    "\"aprs_rotations\":0,\"aprs_read_errors\":0,\"aprs_err\":\"\"}";
/* A fixed station heard direct, as emit_aprs_packet() writes it. */
static const char P1[] =
    "{\"type\":\"aprs_packet\",\"ts\":1793930036,\"src\":\"file:/var/lib/direwolf/aprs.log\","
    "\"seq\":1,\"chan\":0,\"utime\":1793930035,\"source\":\"N0TEST-5\",\"heard\":\"N0TEST-5\","
    "\"direct\":1,\"level\":50,\"error\":0,\"dti\":\"!\",\"name\":\"N0TEST-5\",\"symbol\":\"/#\","
    "\"lat\":10.000000,\"lon\":-20.000000,\"system\":\"DireWolf, WB2OSZ\","
    "\"comment\":\"Test station\"}";
/* Its station record, as emit_aprs_station() writes it. */
static const char S1[] =
    "{\"type\":\"aprs_station\",\"ts\":1793930036,\"call\":\"N0TEST-5\",\"state\":\"live\","
    "\"src\":\"file:/var/lib/direwolf/aprs.log\",\"first_seen\":1793930035,"
    "\"last_seen\":1793930035,\"packets\":1,\"via\":\"N0TEST-5\",\"direct\":1,"
    "\"heard_direct\":1,\"level\":50,\"best_level\":50,\"dti\":\"!\",\"symbol\":\"/#\","
    "\"lat\":10.000000,\"lon\":-20.000000,\"pos_ts\":1793930035,"
    "\"system\":\"DireWolf, WB2OSZ\",\"comment\":\"Test station\"}";
/* A moving station through a digipeater. */
static const char P2[] =
    "{\"type\":\"aprs_packet\",\"ts\":1793930061,\"src\":\"file:/var/lib/direwolf/aprs.log\","
    "\"seq\":2,\"chan\":0,\"utime\":1793930060,\"source\":\"N0TEST-9\",\"heard\":\"N0CALL-1\","
    "\"direct\":0,\"level\":20,\"error\":0,\"dti\":\"=\",\"name\":\"N0TEST-9\",\"symbol\":\"/>\","
    "\"lat\":10.205667,\"lon\":-20.535000,\"speed_kt\":45.0,\"course\":90.0,\"alt_m\":376.1,"
    "\"system\":\"Generic, (obsolete. Digis should use APNxxx instead)\",\"comment\":\" moving\"}";
/* The fixed station sending an object: its position is the object's. */
static const char P3[] =
    "{\"type\":\"aprs_packet\",\"ts\":1793930070,\"src\":\"file:/var/lib/direwolf/aprs.log\","
    "\"seq\":3,\"chan\":0,\"utime\":1793930069,\"source\":\"N0TEST-5\",\"heard\":\"N0CALL-1\","
    "\"direct\":0,\"level\":30,\"dti\":\";\",\"name\":\"TESTOBJ\",\"symbol\":\"/r\","
    "\"lat\":11.000000,\"lon\":-21.000000,\"comment\":\"object note\"}";

static char g_out[262144];

static int route(const web_health_t *h, const char *path, const char *query) {
    web_req_t *rq = calloc(1, sizeof(*rq));
    web_resp_t r;
    if (!rq) return -1;
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query);
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    /* The connection's own buffer size: an answer must fit it. */
    int rc = web_route(rq, h, 1, g_out, 65536, &r);
    free(rq);
    if (rc != 0) return -1;
    g_out[r.out_len < sizeof(g_out) ? r.out_len : sizeof(g_out) - 1] = '\0';
    return r.status;
}

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static void fresh(void) {
    web_aprs_destroy(&A);
    WT_EQ(web_aprs_init(&A), 0);
}

static void health(web_health_t *H, long long now) {
    memset(H, 0, sizeof(*H));
    H->aprs = &A;
    H->wall_s = now;
}

/* The records land where the page reads them: the sensor block, the
 * stations most recently heard first, absent figures null; the object
 * moves neither the sender's position nor its comment, but is one of
 * its packets; ?call= carries the track and the recent packets. */
static void test_aprs_ingest_and_route(void) {
    fresh();
    feed(P1); feed(S1); feed(P2); feed(P3); feed(SH);
    web_health_t H;
    health(&H, T);
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"now\":1793930100,\"src\":\"file:/var/lib/direwolf/aprs.log\",\"records\":1,"
              "\"packet_records\":3,\"evictions\":0,\"aged\":0,\"rejected\":0,\"sensor\":{"
              "\"ts\":1793930100,\"state\":\"live\",\"src\":\"file:/var/lib/direwolf/aprs.log\","
              "\"missing\":0,\"last_read\":1793930099,\"last_packet\":1793930060,\"stations\":2,"
              "\"bytes\":4096,\"lines\":12,\"packets\":11,\"bad_lines\":1,\"overflow\":0,"
              "\"expired\":3,\"truncations\":1,\"rotations\":0,\"read_errors\":0,\"err\":\"\"},"
              "\"total\":2,\"live\":2,\"with_pos\":2,\"heard_direct\":1,\"stations\":["
              "{\"call\":\"N0TEST-5\",\"state\":\"live\",\"first_seen\":1793930035,"
              "\"last_seen\":1793930069,\"packets\":2,\"via\":\"N0CALL-1\",\"direct\":0,"
              "\"heard_direct\":1,\"level\":30,\"best_level\":50,\"dti\":\";\",\"symbol\":\"/#\","
              "\"lat\":10.00000,\"lon\":-20.00000,\"pos_ts\":1793930035,\"speed_kt\":null,"
              "\"course\":null,\"alt_m\":null,\"comment\":\"Test station\",\"status\":\"\","
              "\"system\":\"DireWolf, WB2OSZ\",\"ts\":1793930070,\"records\":3,\"track_n\":1},"
              "{\"call\":\"N0TEST-9\",\"state\":\"live\",\"first_seen\":1793930060,"
              "\"last_seen\":1793930060,\"packets\":1,\"via\":\"N0CALL-1\",\"direct\":0,"
              "\"heard_direct\":0,\"level\":20,\"best_level\":20,\"dti\":\"=\",\"symbol\":\"/\\u003e\","
              "\"lat\":10.20567,\"lon\":-20.53500,\"pos_ts\":1793930060,\"speed_kt\":45.0,"
              "\"course\":90,\"alt_m\":376,\"comment\":\" moving\",\"status\":\"\",");
    WT_HAS(b, "],\"shown\":2,\"cut\":false}");
    WT_LACKS(b, "\"lat\":11.0");
    WT_LACKS(b, "track_pts");
    WT_EQ(route(&H, "/api/aprs", "call=N0TEST-5"), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"now\":1793930100,\"src\":\"file:/var/lib/direwolf/aprs.log\",\"call\":\"N0TEST-5\","
              "\"station\":{\"call\":\"N0TEST-5\",\"state\":\"live\",");
    WT_HAS(b, "\"track_n\":1,\"track_pts\":[[1793930035,10.00000,-20.00000]],"
              "\"packet_cols\":[\"ts\",\"dti\",\"via\",\"direct\",\"level\",\"has_pos\",\"comment\"],"
              "\"packets_recent\":[[1793930035,\"!\",\"N0TEST-5\",1,50,1,\"Test station\"],"
              "[1793930069,\";\",\"N0CALL-1\",0,30,1,\"object note\"]]}}");
    WT_EQ(route(&H, "/api/aprs", "call=N0TEST-7"), 200);
    WT_HAS(body_of(g_out), "\"call\":\"N0TEST-7\",\"station\":null}");
    WT_EQ(route(&H, "/api/aprs", "limit=1"), 200);
    WT_HAS(body_of(g_out), "],\"shown\":1,\"cut\":false}");
    WT_LACKS(body_of(g_out), "N0TEST-9");
    /* The health member. */
    WT_EQ(route(&H, "/api/health", ""), 200);
    WT_HAS(body_of(g_out), "\"aprs\":{\"rows\":2,\"live\":2,\"records\":1,\"packets\":3,"
                           "\"evictions\":0,\"aged\":0,\"rejected\":0,\"sensor_seen\":1}");
    /* Nothing yet: a sensor_health without the block (a sloth with no
     * --aprs) leaves the sensor null. */
    fresh();
    feed("{\"type\":\"sensor_health\",\"ts\":1793930100,\"capture_iface\":\"any\"}");
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    WT_HAS(body_of(g_out), "\"src\":\"\",\"records\":0,\"packet_records\":0,\"evictions\":0,"
                           "\"aged\":0,\"rejected\":0,\"sensor\":null,\"total\":0,\"live\":0,"
                           "\"with_pos\":0,\"heard_direct\":0,\"stations\":[],\"shown\":0,"
                           "\"cut\":false}");
}

/* Every string and figure is checked: a call that is not an AX.25 call
 * rejects the record and counts it; anything else outside its range is
 * absent, never clamped; the query refusals never echo the value. */
static void test_aprs_ranges_and_refusals(void) {
    fresh();
    feed("{\"type\":\"aprs_packet\",\"ts\":1793930100,\"utime\":1793930100,\"source\":\"n0test\"}");
    feed("{\"type\":\"aprs_packet\",\"ts\":1793930100,\"utime\":1793930100,\"source\":\"N0TEST-123\"}");
    feed("{\"type\":\"aprs_packet\",\"ts\":1793930100,\"source\":\"N0TEST\"}");
    feed("{\"type\":\"aprs_station\",\"ts\":1793930100,\"call\":\"N0TEST\",\"state\":\"maybe\","
         "\"first_seen\":1793930100}");
    feed("{\"type\":\"aprs_packet\",\"ts\":1793930100,\"utime\":1793930100,\"source\":\"N0TEST-2\","
         "\"heard\":\"WIDE1 1\",\"level\":1000,\"dti\":\"!!\",\"symbol\":\"/\",\"lat\":91,\"lon\":0,"
         "\"speed_kt\":5000,\"course\":400,\"alt_m\":-2000,\"system\":\"a\\u0001b\","
         "\"comment\":\"ok\"}");
    feed("{\"type\":\"aprs_packet\",\"ts\":1793930101,\"utime\":1793930101,\"source\":\"N0TEST-3\","
         "\"lat\":10.5,\"lon\":20.5,\"speed_kt\":5000,\"course\":400,\"alt_m\":-2000}");
    web_health_t H;
    health(&H, T);
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"rejected\":4,");
    WT_HAS(b, "{\"call\":\"N0TEST-2\",\"state\":\"live\",\"first_seen\":1793930100,"
              "\"last_seen\":1793930100,\"packets\":1,\"via\":\"\",\"direct\":0,"
              "\"heard_direct\":0,\"level\":null,\"best_level\":null,\"dti\":\"\",\"symbol\":\"\","
              "\"lat\":null,\"lon\":null,\"pos_ts\":null,\"speed_kt\":null,\"course\":null,"
              "\"alt_m\":null,\"comment\":\"ok\",\"status\":\"\",\"system\":\"\",");
    WT_HAS(b, "{\"call\":\"N0TEST-3\",\"state\":\"live\",");
    WT_HAS(b, "\"lat\":10.50000,\"lon\":20.50000,\"pos_ts\":1793930101,\"speed_kt\":null,"
              "\"course\":null,\"alt_m\":null,");
    WT_EQ(route(&H, "/api/aprs", "limit=0"), 400);
    WT_HAS(body_of(g_out), "bad_limit");
    WT_EQ(route(&H, "/api/aprs", "limit=1025"), 400);
    WT_EQ(route(&H, "/api/aprs", "call=n0test"), 400);
    WT_HAS(body_of(g_out), "bad_call");
    WT_LACKS(body_of(g_out), "n0test");
    WT_EQ(route(&H, "/api/aprs", "call=N0TEST%27"), 400);
    WT_EQ(route(&H, "/api/aprs", "sort=x"), 400);
    WT_LACKS(body_of(g_out), "sort=x");
    H.aprs = NULL;
    WT_EQ(route(&H, "/api/aprs", ""), 503);
}

/* A gone station is marked, sorted after the live ones and dropped
 * WEB_APRS_GONE_TTL_S later (not counted as aged); a live station quiet
 * past WEB_APRS_TTL_S is dropped and counted; a packet from a gone
 * station starts its next visit afresh. */
static void test_aprs_gone_and_age(void) {
    fresh();
    feed(P1); feed(S1); feed(P2);
    static char line[1024];
    snprintf(line, sizeof(line), "%s", S1);
    char *p = strstr(line, "\"state\":\"live\"");
    memcpy(p, "\"state\":\"gone\"", 14);
    p = strstr(line, "\"ts\":1793930036");
    memcpy(p, "\"ts\":1793933700", 15);
    feed(line);
    web_health_t H;
    health(&H, T + 3600);
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    const char *b = body_of(g_out);
    /* N0TEST-9's last record (ts 1793930061) is past WEB_APRS_TTL_S of
     * the gone record's ts: aged. */
    WT_HAS(b, "\"aged\":1,");
    WT_HAS(b, "\"total\":1,\"live\":0,");
    WT_HAS(b, "{\"call\":\"N0TEST-5\",\"state\":\"gone\",");
    /* Back on the air: a new visit, one packet, a fresh track. */
    snprintf(line, sizeof(line), "%s", P1);
    p = strstr(line, "\"utime\":1793930035");
    memcpy(p, "\"utime\":1793933800", 18);
    p = strstr(line, "\"ts\":1793930036");
    memcpy(p, "\"ts\":1793933801", 15);
    feed(line);
    WT_EQ(route(&H, "/api/aprs", "call=N0TEST-5"), 200);
    WT_HAS(body_of(g_out), "\"state\":\"live\",\"first_seen\":1793933800,\"last_seen\":1793933800,"
                           "\"packets\":1,");
    WT_HAS(body_of(g_out), "\"track_pts\":[[1793933800,10.00000,-20.00000]]");
    /* A gone station goes WEB_APRS_GONE_TTL_S after its gone record. */
    fresh();
    feed(S1);
    snprintf(line, sizeof(line), "%s", S1);
    p = strstr(line, "\"state\":\"live\"");
    memcpy(p, "\"state\":\"gone\"", 14);
    feed(line);
    snprintf(line, sizeof(line), "%s", SH);
    p = strstr(line, "\"ts\":1793930100");
    memcpy(p, "\"ts\":1793931900", 15);    /* 1864 s on: past the 1800 s keep */
    feed(line);
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    WT_HAS(body_of(g_out), "\"aged\":0,");
    WT_HAS(body_of(g_out), "\"total\":0,");
}

/* WEB_APRS_ROWS stations; the least recently reported evicted and
 * counted. Every row with a comment of 128 '<' (six bytes each once
 * escaped): the list stops where the 64 KB answer would not fit and
 * says so, and the route still answers 200. */
static void test_aprs_eviction_and_budget(void) {
    fresh();
    static char line[2048];
    char cm[WEB_APRS_COMMENT_MAX + 1];
    memset(cm, '<', WEB_APRS_COMMENT_MAX);
    cm[WEB_APRS_COMMENT_MAX] = '\0';
    for (int i = 0; i < WEB_APRS_ROWS + 1; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"aprs_packet\",\"ts\":%lld,\"utime\":%lld,\"source\":\"N%dT\","
                 "\"lat\":10.0,\"lon\":20.0,\"comment\":\"%s\"}", T, T + i, i, cm);
        feed(line);
    }
    web_health_t H;
    health(&H, T + 600);
    WT_EQ(route(&H, "/api/aprs", "limit=1"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"evictions\":1,");
    WT_HAS(b, "\"total\":1024,");
    WT_HAS(b, "{\"call\":\"N1024T\",");
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"cut\":true}");
    WT_LACKS(b, "\"call\":\"N0T\"");
    WT_EQ(route(&H, "/api/aprs", "call=N0T"), 200);
    WT_HAS(body_of(g_out), "\"station\":null}");
}

/* The receiver is passive radio: both records are Monitor's and poll
 * types; Monitor and Hybrid answer stations, Local the one out_of_scope
 * body (its query still checked). */
static void test_aprs_scope(void) {
    fresh();
    feed(SH); feed(P1); feed(S1);
    WT_EQ(web_scope_record("aprs_packet"), WEB_SC_M);
    WT_EQ(web_scope_record("aprs_station"), WEB_SC_M);
    WT_ASSERT(web_live_is_poll_type("aprs_packet"));
    WT_ASSERT(web_live_is_poll_type("aprs_station"));
    web_health_t H;
    health(&H, T);
    WT_EQ(route(&H, "/api/aprs", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_EQ(route(&H, "/api/aprs", "scope=hybrid"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_EQ(route(&H, "/api/aprs", "scope=local"), 200);
    WT_HAS(body_of(g_out), "{\"scope\":\"local\",\"out_of_scope\":true,\"reason\":\"APRS stations are the Dire Wolf decoder");
    WT_LACKS(body_of(g_out), "N0TEST");
    WT_EQ(route(&H, "/api/aprs", "scope=local&limit=0"), 400);
    WT_EQ(route(&H, "/api/aprs", "scope=local&call=N0TEST-5"), 200);
    WT_LACKS(body_of(g_out), "Test station");
}

/* The call rule is sloth's (src/aprs.c aprs_call_ok()). */
static void test_aprs_call_rule_is_sloths(void) {
    WT_ASSERT(web_aprs_call_ok("N0TEST"));
    WT_ASSERT(web_aprs_call_ok("N0TEST-15"));
    WT_ASSERT(web_aprs_call_ok("N0CALL-AB"));
    WT_ASSERT(!web_aprs_call_ok("N0TESTX"));
    WT_ASSERT(!web_aprs_call_ok("N0TEST-"));
    WT_ASSERT(!web_aprs_call_ok("N0TEST-123"));
    WT_ASSERT(!web_aprs_call_ok("n0test"));
    WT_ASSERT(!web_aprs_call_ok(""));
    WT_ASSERT(!web_aprs_call_ok(NULL));
}

/* The page's half: the tab after ADS-B, the view, the module's hook,
 * the scope rule; the tables are app.js's DataTable; every remote
 * string goes through textContent (el()); the history routes. */
static void test_aprs_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "<li><button type=\"button\" class=\"go\" id=\"nav-adsb\">ADS-B</button></li>\n"
              "      <li><button type=\"button\" class=\"go\" id=\"nav-aprs\">APRS</button></li>");
    WT_HAS(p, "  $(\"nav-aprs\").addEventListener(\"click\", function () { show(\"aprs\"); });");
    WT_HAS(p, "    if (v === \"aprs\" && window.SlothAprs) SlothAprs.show();");
    WT_HAS(p, "    $(\"v-aprs\").classList.toggle(\"scoped-out\", SCOPE === \"local\");");
    WT_HAS(p, "<div id=\"v-aprs\" hidden>");
    WT_HAS(p, "<section class=\"panel scope-empty\" id=\"aprs-scope-empty\">");
    WT_HAS(p, "<div class=\"hscroll\" id=\"aprs-box\"><div class=\"aprsrow dhead\" id=\"aprs-thead\"></div><div id=\"aprs-rows\"></div></div>");
    WT_HAS(p, "<div class=\"hscroll\" id=\"aprs-seen-box\"><div class=\"histrow dhead\" id=\"aprs-seen-thead\"></div><div id=\"aprs-seen-rows\"></div></div>");
    WT_HAS(p, "  function table() {\n"
              "    if (T || !window.SlothTables || !$(\"aprs-box\")) return T;\n"
              "    T = window.SlothTables.make({ id: \"aprs\", label: \"stations\", box: $(\"aprs-box\"),\n"
              "      head: $(\"aprs-thead\"), reset: $(\"aprs-tools\"), redraw: drawRows, cols: COLS });\n"
              "    return T;\n"
              "  }");
    WT_HAS(p, "    ST = window.SlothTables.make({ id: \"aprs-seen\", label: \"stations seen\", box: $(\"aprs-seen-box\"),\n"
              "      head: $(\"aprs-seen-thead\"), reset: $(\"aprs-seen-tools\"), redraw: drawSeen, cols: SEEN_COLS });");
    WT_HAS(p, "  function el(tag, cls, text) {\n"
              "    var e = document.createElement(tag);\n"
              "    if (cls) e.className = cls;\n"
              "    if (text !== undefined && text !== null) e.textContent = String(text);\n"
              "    return e;\n"
              "  }");
    WT_HAS(p, "    getJSON(\"/api/aprs?call=\" + encodeURIComponent(call)).then(function (j) {");
    WT_HAS(p, "    getJSON(\"/api/aprs/seen?days=\" + encodeURIComponent(seenDays()) + \"&limit=\" + SEEN_PAGE +\n"
              "            \"&offset=\" + off + (q ? \"&q=\" + encodeURIComponent(q) : \"\")).then(function (j) {");
    WT_HAS(p, "    getJSON(\"/api/aprs/station?call=\" + encodeURIComponent(call) + \"&days=\" + encodeURIComponent(seenDays())).then(function (j) {");
    WT_HAS(p, "    if (q && !/^[0-9A-Za-z-]{1,9}$/.test(q)) { set(\"aprs-seen-count\", \"search: letters, digits and - only\"); return; }");
    WT_HAS(p, "      if (j.out_of_scope) return;");
    WT_HAS(p, "  window.SlothAprs = { show: show };");
    /* No markup built from a string in the module. */
    const char *m = strstr(p, "window.SlothAprs = { show: show };");
    const char *s = strstr(p, "// slothweb: the APRS panel");
    WT_ASSERT(s && m && s < m);
    if (s && m) {
        size_t n = (size_t)(m - s);
        char *mod = malloc(n + 1);
        WT_ASSERT(mod != NULL);
        if (mod) {
            memcpy(mod, s, n);
            mod[n] = '\0';
            WT_LACKS(mod, "innerHTML");
            WT_LACKS(mod, "insertAdjacentHTML");
            WT_LACKS(mod, "http://");
            WT_LACKS(mod, "https://");
            free(mod);
        }
    }
}

/* ── history (web_aprshist.h) ─────────────────────────────────────── */

static web_m4_t     m4;
static web_health_t HH;

/* No sloth.db: 503 no_sloth_db after the query is checked. */
static void test_aprshist_no_db(void) {
    memset(&m4, 0, sizeof(m4));
    memset(&HH, 0, sizeof(HH));
    HH.wall_s = SDB_NOW;
    HH.m4 = &m4;
    WT_EQ(route(&HH, "/api/aprs/seen", ""), 503);
    WT_HAS(body_of(g_out), "no_sloth_db");
    WT_EQ(route(&HH, "/api/aprs/station", "call=N0TEST-5"), 503);
    WT_EQ(route(&HH, "/api/aprs/seen", "days=0"), 400);
    WT_HAS(body_of(g_out), "bad_days");
    WT_EQ(route(&HH, "/api/aprs/seen", "days=401"), 400);
    WT_EQ(route(&HH, "/api/aprs/seen", "limit=101"), 400);
    WT_EQ(route(&HH, "/api/aprs/seen", "q=n0%25"), 400);
    WT_HAS(body_of(g_out), "bad_q");
    WT_EQ(route(&HH, "/api/aprs/seen", "q=n0_"), 400);
    WT_EQ(route(&HH, "/api/aprs/seen", "q=N0TEST-123"), 400);
    WT_EQ(route(&HH, "/api/aprs/seen", "offset=100001"), 400);
    WT_EQ(route(&HH, "/api/aprs/station", ""), 400);
    WT_HAS(body_of(g_out), "bad_call");
    WT_EQ(route(&HH, "/api/aprs/station", "call=n0test"), 400);
    WT_EQ(route(&HH, "/api/aprs/station", "call=N0TEST&sort=x"), 400);
}

#ifdef WITH_SQLITE

#define TN SDB_NOW

static char g_dir[TEST_TMP_MAX];
static char g_db[128];
static web_slothdb_t sdb;

static void db_up(int version) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-aprs-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, version, 0), 0);
    web_slothdb_init(&sdb, g_db, NULL);
    memset(&m4, 0, sizeof(m4));
    m4.sdb = &sdb;
    memset(&HH, 0, sizeof(HH));
    HH.wall_s = TN;
    HH.m4 = &m4;
}

static void db_down(void) {
    web_slothdb_destroy(&sdb);
    unlink(g_db);
    rmdir(g_dir);
}

/* Rows as write_aprs() leaves them: two stations in the week, one nine
 * days old; N0TEST-5's packets, one an object. */
static void seed_aprs(void) {
    char sql[4096];
    snprintf(sql, sizeof(sql),
        "INSERT INTO aprs_stations (call,first_seen,last_seen,visit_first,visits,packets,"
        "via,heard_direct,best_level,dti,symbol,lat,lon,pos_ts,comment,status,system) VALUES"
        " ('N0TEST-5',%lld,%lld,%lld,2,3,'N0CALL-1',1,70,';','/#',10.0,-20.0,%lld,"
        "'on the air',NULL,'DireWolf, WB2OSZ'),"
        " ('N0TEST-9',%lld,%lld,%lld,1,1,NULL,0,NULL,'=','/>',10.2,-20.5,%lld,' moving',"
        "'En Route',NULL),"
        " ('N0CALL-1',%lld,%lld,%lld,1,4,'N0CALL-1',1,40,'!','/#',NULL,NULL,NULL,NULL,NULL,NULL);"
        "INSERT INTO aprs_packets (last_seen,source,heard,dti,name,symbol,lat,lon,speed_kt,"
        "course,alt_m,level,status,comment) VALUES"
        " (%lld,'N0TEST-5','N0TEST-5','!','N0TEST-5','/#',10.0,-20.0,NULL,NULL,NULL,50,NULL,"
        "'Test station'),"
        " (%lld,'N0TEST-5','N0CALL-1','>','N0TEST-5',NULL,NULL,NULL,NULL,NULL,NULL,20,NULL,"
        "'on the air'),"
        " (%lld,'N0TEST-5','N0CALL-1',';','TESTOBJ','/r',11.0,-21.0,NULL,NULL,NULL,70,NULL,"
        "'object note'),"
        " (%lld,'N0TEST-9',NULL,'=','N0TEST-9','/>',10.2,-20.5,45.0,90.0,376.1,NULL,'En Route',"
        "' moving'),"
        " (%lld,'N0TEST-5','N0TEST-5','!','N0TEST-5','/#',10.0,-20.0,NULL,NULL,NULL,50,NULL,"
        "'old');",
        TN - 7200, TN - 60, TN - 3000, TN - 7200,
        TN - 600, TN - 600, TN - 600, TN - 600,
        TN - 9 * 86400LL, TN - 9 * 86400LL, TN - 9 * 86400LL,
        TN - 7200, TN - 3000, TN - 60, TN - 600, TN - 9 * 86400LL);
    WT_EQ(sdb_exec(g_db, sql), 0);
}

static void test_aprshist_seen_and_station(void) {
    db_up(db_schema_version());
    seed_aprs();
    WT_EQ(route(&HH, "/api/aprs/seen", ""), 200);
    const char *b = body_of(g_out);
    char want[1024];
    snprintf(want, sizeof(want), "\"have\":true,\"stations\":[{\"call\":\"N0TEST-5\","
             "\"first_seen\":%lld,\"last_seen\":%lld,\"visits\":2,\"packets\":3,"
             "\"via\":\"N0CALL-1\",\"heard_direct\":1,\"best_level\":70,\"dti\":\";\","
             "\"symbol\":\"/#\",\"lat\":10.00000,\"lon\":-20.00000,\"pos_ts\":%lld,"
             "\"comment\":\"on the air\"},{\"call\":\"N0TEST-9\",", TN - 7200, TN - 60, TN - 7200);
    WT_HAS(b, want);
    WT_HAS(b, "\"via\":\"\",\"heard_direct\":0,\"best_level\":null,");
    WT_HAS(b, "\"total\":2,\"more\":false}");
    WT_LACKS(b, "N0CALL-1\",\"first_seen");     /* 9 days: outside 7 */
    WT_LACKS(b, "DireWolf");                    /* the inventory has no system */
    WT_EQ(route(&HH, "/api/aprs/seen", "days=30"), 200);
    WT_HAS(body_of(g_out), "{\"call\":\"N0CALL-1\",");
    WT_EQ(route(&HH, "/api/aprs/seen", "limit=1"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,\"more\":true}");
    WT_EQ(route(&HH, "/api/aprs/seen", "limit=1&offset=1"), 200);
    WT_HAS(body_of(g_out), "\"stations\":[{\"call\":\"N0TEST-9\"");
    WT_EQ(route(&HH, "/api/aprs/seen", "q=n0test-9"), 200);
    WT_HAS(body_of(g_out), "\"q\":\"N0TEST-9\",");
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_EQ(route(&HH, "/api/aprs/seen", "q=N0T"), 200);
    WT_HAS(body_of(g_out), "\"total\":2,");
    WT_EQ(route(&HH, "/api/aprs/seen", "q=ZZ"), 200);
    WT_HAS(body_of(g_out), "\"stations\":[],\"total\":0,");
    /* One station: its row (with status and system) and its packets in
     * the window, oldest first; the object is its own packet. */
    WT_EQ(route(&HH, "/api/aprs/station", "call=N0TEST-5"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"station\":{\"call\":\"N0TEST-5\",");
    WT_HAS(b, "\"comment\":\"on the air\",\"status\":\"\",\"system\":\"DireWolf, WB2OSZ\"}");
    snprintf(want, sizeof(want),
             "\"cols\":[\"ts\",\"heard\",\"dti\",\"name\",\"symbol\",\"lat\",\"lon\",\"speed_kt\","
             "\"course\",\"alt_m\",\"level\",\"status\",\"comment\"],\"packets\":["
             "[%lld,\"N0TEST-5\",\"!\",\"N0TEST-5\",\"/#\",10.00000,-20.00000,null,null,null,50,"
             "\"\",\"Test station\"],[%lld,\"N0CALL-1\",\"\\u003e\",\"N0TEST-5\",\"\",null,null,null,null,"
             "null,20,\"\",\"on the air\"],[%lld,\"N0CALL-1\",\";\",\"TESTOBJ\",\"/r\",11.00000,"
             "-21.00000,null,null,null,70,\"\",\"object note\"]],\"total\":3,\"cut\":false}",
             TN - 7200, TN - 3000, TN - 60);
    WT_HAS(b, want);
    WT_EQ(route(&HH, "/api/aprs/station", "call=N0TEST-5&days=30"), 200);
    WT_HAS(body_of(g_out), "\"total\":4,\"cut\":false}");
    WT_EQ(route(&HH, "/api/aprs/station", "call=N0TEST-7"), 200);
    WT_HAS(body_of(g_out), "\"station\":null,");
    WT_HAS(body_of(g_out), "\"packets\":[],\"total\":0,\"cut\":false}");
    /* Local: the receiver is passive radio. */
    WT_EQ(route(&HH, "/api/aprs/seen", "scope=local"), 200);
    WT_HAS(body_of(g_out), "\"out_of_scope\":true,\"reason\":\"APRS stations are the Dire Wolf decoder");
    WT_LACKS(body_of(g_out), "N0TEST");
    WT_EQ(route(&HH, "/api/aprs/station", "scope=local&call=N0TEST-5"), 200);
    WT_HAS(body_of(g_out), "\"out_of_scope\":true");
    WT_LACKS(body_of(g_out), "on the air");
    WT_EQ(route(&HH, "/api/aprs/station", "scope=local&call=zz"), 400);
    WT_EQ(route(&HH, "/api/aprs/seen", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "\"total\":2,");
    db_down();
}

/* 400 packets whose comment is 128 '<' (768 bytes escaped): the answer
 * keeps the newest that fit the 64 KB buffer, says "cut", answers 200.
 * 100 stations with that comment: one whole inventory page. */
static void test_aprshist_budget(void) {
    db_up(db_schema_version());
    char cm[129];
    memset(cm, '<', 128);
    cm[128] = '\0';
    static char sql[1 << 18];
    int off = snprintf(sql, sizeof(sql), "INSERT INTO aprs_stations (call,first_seen,"
                       "last_seen,visit_first,comment) VALUES ");
    for (int i = 0; i < 100; i++)
        off += snprintf(sql + off, sizeof(sql) - (size_t)off, "%s('N%dT',%lld,%lld,%lld,'%s')",
                        i ? "," : "", i, TN - 100, TN - 100 + i, TN - 100, cm);
    snprintf(sql + off, sizeof(sql) - (size_t)off, ";");
    WT_EQ(sdb_exec(g_db, sql), 0);
    off = snprintf(sql, sizeof(sql), "INSERT INTO aprs_packets (last_seen,source,comment,"
                   "status) VALUES ");
    for (int i = 0; i < 400; i++)
        off += snprintf(sql + off, sizeof(sql) - (size_t)off, "%s(%lld,'N0T','%s','%.64s')",
                        i ? "," : "", TN - 1000 + i, cm, cm);
    snprintf(sql + off, sizeof(sql) - (size_t)off, ";");
    WT_EQ(sdb_exec(g_db, sql), 0);
    WT_EQ(route(&HH, "/api/aprs/station", "call=N0T"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"cut\":true}");
    char newest[32];
    snprintf(newest, sizeof(newest), "[%lld,", TN - 1000 + 399);
    WT_HAS(b, newest);
    snprintf(newest, sizeof(newest), "[%lld,", TN - 1000);
    WT_LACKS(b, newest);
    /* A full inventory page of such rows fits whole: the comment is cut
     * to WEB_APRSHIST_SEEN_CM there, so its byte guard is a backstop
     * these caps never reach (not claimed as exercised here). */
    WT_EQ(route(&HH, "/api/aprs/seen", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"total\":100,\"more\":false}");
    WT_HAS(b, "{\"call\":\"N99T\",");
    WT_HAS(b, "{\"call\":\"N0T\",");
    db_down();
}

/* A sloth.db from before the tables: an empty answer that says so,
 * never an error. */
static void test_aprshist_older_file(void) {
    db_up(12);
    WT_EQ(route(&HH, "/api/aprs/seen", ""), 200);
    WT_HAS(body_of(g_out), "\"db_schema\":12,\"have\":false,\"stations\":[],\"total\":0,");
    WT_EQ(route(&HH, "/api/aprs/station", "call=N0TEST-5"), 200);
    WT_HAS(body_of(g_out), "\"have\":false,\"station\":null,");
    db_down();
}

#endif

void run_aprs_tests(void) {
    WT_RUN(test_aprs_ingest_and_route);
    WT_RUN(test_aprs_ranges_and_refusals);
    WT_RUN(test_aprs_gone_and_age);
    WT_RUN(test_aprs_eviction_and_budget);
    WT_RUN(test_aprs_scope);
    WT_RUN(test_aprs_call_rule_is_sloths);
    WT_RUN(test_aprs_page);
    WT_RUN(test_aprshist_no_db);
#ifdef WITH_SQLITE
    WT_RUN(test_aprshist_seen_and_station);
    WT_RUN(test_aprshist_budget);
    WT_RUN(test_aprshist_older_file);
#endif
    web_aprs_destroy(&A);
}
