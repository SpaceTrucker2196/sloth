/* Direction finding across monitor radios (web_df.h): sloth-wifi's
 * `df_radio` and `wifi_df` records in the shape src/jsonl.c
 * jsonl_emit_wifi_df() writes them, kept by slothweb, answered on
 * /api/df, and the page's half pinned out of the served page.
 *
 * Absence assertions, each seen red under the mutation named beside it
 * and restored. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "web_df.h"
#include "web_ingest.h"
#include "web_jsonl.h"
#include "web_routes.h"
#include "web_scope.h"
#include "wtest.h"

static web_df_t D;
static web_jrec_t R;
static int inited;
static char g_out[131072];

#define MONO0 900000LL
#define T     1800000000LL

static void feed_at(const char *line, long long ms) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_df_record(&D, &R, ms);
}
static void feed(const char *line) { feed_at(line, MONO0); }

static void fresh(void) {
    if (inited) web_df_destroy(&D);
    WT_EQ(web_df_init(&D), 0);
    inited = 1;
}

static int route(const char *query, long long now_ms) {
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.df = &D;
    h.wall_s = T + 5;
    h.now_ms = now_ms;
    web_req_t *rq = calloc(1, sizeof(*rq));
    web_resp_t r;
    if (!rq) return -1;
    snprintf(rq->path, sizeof(rq->path), "%s", "/api/df");
    snprintf(rq->query, sizeof(rq->query), "%s", query);
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    int rc = web_route(rq, &h, 1, g_out, sizeof(g_out), &r);
    free(rq);
    if (rc != 0) return -1;
    g_out[r.out_len] = '\0';
    return r.status;
}

static const char *body(void) {
    const char *sep = strstr(g_out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static const char HEALTH22[] = "{\"type\":\"sensor_health\",\"ts\":1800000000,\"jsonl_version\":\"2.2.0\"}";
static const char RADIO0[] =
    "{\"type\":\"df_radio\",\"ts\":1800000000,\"radio\":0,\"iface\":\"alfa0\",\"role\":\"sensor\","
    "\"pos_m\":0.00,\"open\":1,\"running\":1,\"noted\":5120}";
static const char RADIO1[] =
    "{\"type\":\"df_radio\",\"ts\":1800000000,\"radio\":1,\"iface\":\"alfa1\",\"role\":\"df\","
    "\"pos_m\":1.00,\"open\":1,\"running\":1,\"noted\":4800,\"bias_db\":-7.50,"
    "\"frames\":9000,\"rejects\":12,\"retune_failures\":1}";
static const char LEAN[] =
    "{\"type\":\"wifi_df\",\"ts\":1800000000,\"mac\":\"02:11:22:33:44:55\",\"channel\":6,"
    "\"heard_by\":2,\"quality\":\"lean\",\"best_radio\":1,\"best_iface\":\"alfa1\","
    "\"margin_db\":9.40,\"along_m\":0.90,\"rssi\":[-61.0,-59.1],\"level\":[-61.0,-51.6],"
    "\"last_seen\":1799999990}";
static const char WEAK[] =
    "{\"type\":\"wifi_df\",\"ts\":1800000000,\"mac\":\"0a:bb:00:00:00:09\",\"channel\":11,"
    "\"heard_by\":2,\"quality\":\"weak\",\"best_radio\":0,\"best_iface\":\"alfa0\","
    "\"margin_db\":1.20,\"rssi\":[-70.0,null],\"level\":[-70.0,null],\"last_seen\":1799999995}";

/* Before anything: "not known", never "off". With a 2.1.0 stream:
 * "does not report". Seen red with web_df_reported() answering 1 for
 * 2.1.0 (the MINOR bound dropped). */
static void test_webdf_reported(void) {
    fresh();
    WT_EQ(web_df_reported(&D), -1);
    WT_EQ(web_df_reported(NULL), -1);
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"reported\":null,\"jsonl_version\":null,\"radios\":[],\"emitters\":[]");
    feed("{\"type\":\"sensor_health\",\"ts\":1,\"jsonl_version\":\"2.1.0\"}");
    WT_EQ(web_df_reported(&D), 0);
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"reported\":false,\"jsonl_version\":\"2.1.0\"");
    feed("{\"type\":\"sensor_health\",\"ts\":1,\"jsonl_version\":\"1.9.0\"}");
    WT_EQ(web_df_reported(&D), 0);
    feed("{\"type\":\"sensor_health\",\"ts\":1}");            /* before 1.0.0 */
    WT_EQ(web_df_reported(&D), 0);
    feed(HEALTH22);
    WT_EQ(web_df_reported(&D), 1);
    feed("{\"type\":\"sensor_health\",\"ts\":1,\"jsonl_version\":\"two\"}");   /* ignored */
    WT_EQ(web_df_reported(&D), 1);
    feed("{\"type\":\"sensor_health\",\"ts\":1,\"jsonl_version\":\"3.0.0\"}");
    WT_EQ(web_df_reported(&D), 1);
    WT_EQ(D.records, 0);
}

/* Both records on the route, every member; the lean row before the
 * weak one; the arrays not carried. Seen red (weak first) with cmp_em()
 * comparing the quality the other way. */
static void test_webdf_route(void) {
    fresh();
    feed(HEALTH22);
    feed(WEAK);
    feed(RADIO1);
    feed(LEAN);
    feed(RADIO0);
    WT_EQ(D.records, 4);
    WT_EQ(D.rejected, 0);
    WT_EQ(route("", MONO0 + 4000), 200);
    const char *b = body();
    WT_HAS(b, "{\"now\":1800000005,\"reported\":true,\"jsonl_version\":\"2.2.0\",\"radios\":["
              "{\"radio\":0,\"iface\":\"alfa0\",\"role\":\"sensor\",\"pos_m\":0.00,\"open\":true,"
              "\"running\":true,\"noted\":5120,\"ts\":1800000000,\"age_s\":4},"
              "{\"radio\":1,\"iface\":\"alfa1\",\"role\":\"df\",\"pos_m\":1.00,\"open\":true,"
              "\"running\":true,\"noted\":4800,\"bias_db\":-7.50,\"frames\":9000,\"rejects\":12,"
              "\"retune_failures\":1,\"ts\":1800000000,\"age_s\":4}]");
    WT_HAS(b, "\"emitters\":[{\"mac\":\"02:11:22:33:44:55\",\"channel\":6,\"heard_by\":2,"
              "\"quality\":\"lean\",\"best_radio\":1,\"best_iface\":\"alfa1\",\"margin_db\":9.40,"
              "\"along_m\":0.90,\"last_seen\":1799999990,\"age_s\":4},"
              "{\"mac\":\"0a:bb:00:00:00:09\",\"channel\":11,\"heard_by\":2,\"quality\":\"weak\","
              "\"best_radio\":0,\"best_iface\":\"alfa0\",\"margin_db\":1.20,"
              "\"last_seen\":1799999995,\"age_s\":4}]");
    WT_HAS(b, "\"held\":2,\"stale\":0,\"records\":4,\"rejected\":0,\"evicted\":0}");
    WT_LACKS(b, "rssi");
    WT_LACKS(b, "level");
    /* A newer record replaces its key's row. */
    feed("{\"type\":\"wifi_df\",\"ts\":1800000010,\"mac\":\"02:11:22:33:44:55\",\"channel\":6,"
         "\"heard_by\":2,\"quality\":\"weak\",\"best_radio\":0,\"best_iface\":\"alfa0\","
         "\"margin_db\":0.50,\"along_m\":0.48,\"last_seen\":1800000009}");
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"held\":2,");
    WT_LACKS(body(), "\"quality\":\"lean\"");
    WT_HAS(body(), "\"margin_db\":0.50,\"along_m\":0.48");
    /* No parameters. */
    WT_EQ(route("limit=3", MONO0), 400);
    WT_HAS(body(), "unknown_parameter");
    /* No table bound. */
    size_t len = 0;
    int st = 0;
    WT_EQ(web_df_route(NULL, "", T, MONO0, 0, g_out, sizeof(g_out), &len, &st), 0);
    WT_EQ(st, 503);
}

/* A malformed record is refused whole and counted: a radio past the
 * table, a role that is not one, radio 0 not the sensor, a name with a
 * space or markup, one counter without the others, a position past the
 * baseline's bound; a bad address, a quality that is not one, a
 * negative margin, a missing margin, a loudest radio past the table.
 * Seen red (the row kept) with jiface()'s character check removed, and
 * with radio_parse()'s sensor check removed. */
static void test_webdf_refuses(void) {
    fresh();
    static const char *const BAD[] = {
        "{\"type\":\"df_radio\",\"ts\":1,\"radio\":4,\"iface\":\"alfa4\",\"role\":\"df\","
        "\"open\":1,\"running\":1,\"noted\":1}",
        "{\"type\":\"df_radio\",\"ts\":1,\"radio\":1,\"iface\":\"alfa1\",\"role\":\"spare\","
        "\"open\":1,\"running\":1,\"noted\":1}",
        "{\"type\":\"df_radio\",\"ts\":1,\"radio\":0,\"iface\":\"alfa0\",\"role\":\"df\","
        "\"open\":1,\"running\":1,\"noted\":1}",
        "{\"type\":\"df_radio\",\"ts\":1,\"radio\":1,\"iface\":\"alfa1\",\"role\":\"sensor\","
        "\"open\":1,\"running\":1,\"noted\":1}",
        "{\"type\":\"df_radio\",\"ts\":1,\"radio\":1,\"iface\":\"al fa\",\"role\":\"df\","
        "\"open\":1,\"running\":1,\"noted\":1}",
        "{\"type\":\"df_radio\",\"ts\":1,\"radio\":1,\"iface\":\"<b>\\u00e9\",\"role\":\"df\","
        "\"open\":1,\"running\":1,\"noted\":1}",
        "{\"type\":\"df_radio\",\"ts\":1,\"radio\":1,\"iface\":\"0123456789abcdef\",\"role\":\"df\","
        "\"open\":1,\"running\":1,\"noted\":1}",
        "{\"type\":\"df_radio\",\"ts\":1,\"radio\":1,\"iface\":\"alfa1\",\"role\":\"df\","
        "\"open\":2,\"running\":1,\"noted\":1}",
        "{\"type\":\"df_radio\",\"ts\":1,\"radio\":1,\"iface\":\"alfa1\",\"role\":\"df\","
        "\"open\":1,\"running\":1,\"noted\":1,\"frames\":5}",
        "{\"type\":\"df_radio\",\"ts\":1,\"radio\":1,\"iface\":\"alfa1\",\"role\":\"df\","
        "\"pos_m\":1000.5,\"open\":1,\"running\":1,\"noted\":1}",
        "{\"type\":\"df_radio\",\"ts\":1,\"radio\":1,\"iface\":\"alfa1\",\"role\":\"df\","
        "\"open\":1,\"running\":1,\"noted\":1,\"bias_db\":\"loud\"}",
        "{\"type\":\"wifi_df\",\"ts\":1,\"mac\":\"02:11:22:33:44\",\"channel\":6,\"heard_by\":2,"
        "\"quality\":\"lean\",\"best_radio\":1,\"margin_db\":9.4,\"last_seen\":1}",
        "{\"type\":\"wifi_df\",\"ts\":1,\"mac\":\"02:11:22:33:44:55\",\"channel\":6,\"heard_by\":2,"
        "\"quality\":\"north\",\"best_radio\":1,\"margin_db\":9.4,\"last_seen\":1}",
        "{\"type\":\"wifi_df\",\"ts\":1,\"mac\":\"02:11:22:33:44:55\",\"channel\":6,\"heard_by\":2,"
        "\"quality\":\"lean\",\"best_radio\":1,\"margin_db\":-9.4,\"last_seen\":1}",
        "{\"type\":\"wifi_df\",\"ts\":1,\"mac\":\"02:11:22:33:44:55\",\"channel\":6,\"heard_by\":2,"
        "\"quality\":\"lean\",\"best_radio\":1,\"last_seen\":1}",
        "{\"type\":\"wifi_df\",\"ts\":1,\"mac\":\"02:11:22:33:44:55\",\"channel\":6,\"heard_by\":2,"
        "\"quality\":\"lean\",\"best_radio\":4,\"margin_db\":9.4,\"last_seen\":1}",
        "{\"type\":\"wifi_df\",\"ts\":1,\"mac\":\"02:11:22:33:44:55\",\"channel\":6,\"heard_by\":5,"
        "\"quality\":\"lean\",\"best_radio\":1,\"margin_db\":9.4,\"last_seen\":1}",
        "{\"type\":\"wifi_df\",\"ts\":1,\"mac\":\"02:11:22:33:44:55\",\"channel\":6,\"heard_by\":2,"
        "\"quality\":\"lean\",\"best_radio\":1,\"best_iface\":\"a/b\",\"margin_db\":9.4,\"last_seen\":1}",
        "{\"type\":\"wifi_df\",\"ts\":1,\"mac\":\"02:11:22:33:44:55\",\"channel\":6,\"heard_by\":2,"
        "\"quality\":\"lean\",\"best_radio\":1,\"margin_db\":9.4,\"along_m\":2000,\"last_seen\":1}",
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) feed(BAD[i]);
    WT_EQ(D.rejected, sizeof(BAD) / sizeof(BAD[0]));
    WT_EQ(D.records, sizeof(BAD) / sizeof(BAD[0]));
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"radios\":[],\"emitters\":[],\"held\":0");
    /* What sloth can write and the bounds allow: no position, no bias,
     * no counters, a best_radio of -1 with no name, whole numbers. */
    feed("{\"type\":\"df_radio\",\"ts\":1,\"radio\":3,\"iface\":\"wlx00c0cabce5a5\",\"role\":\"df\","
         "\"pos_m\":-1000,\"open\":0,\"running\":0,\"noted\":0}");
    feed("{\"type\":\"wifi_df\",\"ts\":1,\"mac\":\"02:11:22:33:44:55\",\"channel\":0,\"heard_by\":2,"
         "\"quality\":\"none\",\"best_radio\":-1,\"margin_db\":0,\"last_seen\":1}");
    WT_EQ(D.rejected, sizeof(BAD) / sizeof(BAD[0]));
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "{\"radio\":3,\"iface\":\"wlx00c0cabce5a5\",\"role\":\"df\",\"pos_m\":-1000.00,"
                   "\"open\":false,\"running\":false,\"noted\":0,\"ts\":1,\"age_s\":0}");
    WT_HAS(body(), "\"quality\":\"none\",\"best_radio\":-1,\"margin_db\":0.00,\"last_seen\":1");
    /* Any other record is not this module's, and not counted. */
    unsigned long before = D.records;
    feed("{\"type\":\"beacon\",\"ts\":1,\"bssid\":\"02:11:22:33:44:55\"}");
    WT_EQ(D.records, before);
}

static void em_at(int i, long long ms) {
    char line[512];
    snprintf(line, sizeof(line),
             "{\"type\":\"wifi_df\",\"ts\":1800000000,\"mac\":\"0a:bb:00:00:%02x:%02x\",\"channel\":1,"
             "\"heard_by\":2,\"quality\":\"lean\",\"best_radio\":1,\"best_iface\":\"alfa1\","
             "\"margin_db\":%d.00,\"along_m\":0.75,\"last_seen\":1800000000}",
             i >> 8, i & 255, 6 + i % 100);
    feed_at(line, ms);
}

/* A row not refreshed for WEB_DF_STALE_MS is left out and counted. A
 * full table gives a new transmitter the row written longest ago, and
 * counts it when that row was still fresh. The answer carries at most
 * WEB_DF_OUT rows, and says how many were fresh. Seen red (the newest
 * row evicted) with the oldest search comparing the other way. */
static void test_webdf_stale_and_bounds(void) {
    fresh();
    feed(RADIO0);
    for (int i = 0; i < WEB_DF_EMITTERS; i++) em_at(i, MONO0 + i);
    WT_EQ(D.evicted, 0);
    WT_EQ(route("", MONO0 + 1000), 200);
    WT_HAS(body(), "\"held\":512,\"stale\":0");
    int rows = 0;
    for (const char *q = strstr(body(), "{\"mac\":"); q; q = strstr(q + 1, "{\"mac\":")) rows++;
    WT_EQ(rows, WEB_DF_OUT);
    /* The widest margin leads. */
    WT_HAS(body(), "\"emitters\":[{\"mac\":\"0a:bb:00:00:00:63\"");
    /* Full of fresh rows: the first written gives way. */
    em_at(1000, MONO0 + 2000);
    WT_EQ(D.evicted, 1);
    int held0 = 0, held1000 = 0, held1 = 0;
    for (int i = 0; i < WEB_DF_EMITTERS; i++) {
        static const uint8_t m0[6] = { 0x0a, 0xbb, 0, 0, 0, 0 }, m1[6] = { 0x0a, 0xbb, 0, 0, 0, 1 },
                             mk[6] = { 0x0a, 0xbb, 0, 0, 0x03, 0xe8 };
        if (!memcmp(D.em[i].mac, m0, 6)) held0++;
        if (!memcmp(D.em[i].mac, m1, 6)) held1++;
        if (!memcmp(D.em[i].mac, mk, 6)) held1000++;
    }
    WT_EQ(held0, 0);
    WT_EQ(held1, 1);
    WT_EQ(held1000, 1);
    /* Past the stale bound: every row left out, the radio with them,
     * and a new transmitter takes a stale row without an eviction. */
    long long later = MONO0 + 2000 + WEB_DF_STALE_MS + 1000;
    WT_EQ(route("", later), 200);
    WT_HAS(body(), "\"radios\":[],\"emitters\":[],\"held\":0,\"stale\":513");
    em_at(2000, later);
    WT_EQ(D.evicted, 1);
    WT_EQ(route("", later), 200);
    WT_HAS(body(), "\"held\":1,\"stale\":512");
}

/* The worst-case answer fits the route's buffer: four radios with
 * every member, WEB_DF_OUT rows with every member at its widest. */
static void test_webdf_worst_case_fits(void) {
    fresh();
    char line[512];
    for (int i = 0; i < WEB_DF_RADIOS; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"df_radio\",\"ts\":99999999999,\"radio\":%d,\"iface\":\"wlx00c0cabce5a%d\","
                 "\"role\":\"%s\",\"pos_m\":-999.99,\"open\":1,\"running\":1,\"noted\":1000000000000"
                 "%s}", i, i, i ? "df" : "sensor",
                 i ? ",\"bias_db\":-199.99,\"frames\":1000000000000,\"rejects\":1000000000000,"
                     "\"retune_failures\":1000000000000" : "");
        feed(line);
    }
    for (int i = 0; i < WEB_DF_EMITTERS; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"wifi_df\",\"ts\":99999999999,\"mac\":\"0a:bb:00:00:%02x:%02x\","
                 "\"channel\":1000,\"heard_by\":4,\"quality\":\"lean\",\"best_radio\":3,"
                 "\"best_iface\":\"wlx00c0cabce5a3\",\"margin_db\":199.99,\"along_m\":-999.99,"
                 "\"last_seen\":99999999999}", i >> 8, i & 255);
        feed(line);
    }
    WT_EQ(D.rejected, 0);
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"held\":512,");
    WT_ASSERT(strlen(body()) > 20000);
}

/* Local: the query is still checked, then the one out_of_scope answer. */
static void test_webdf_scope(void) {
    fresh();
    feed(LEAN);
    WT_EQ(route("scope=local", MONO0), 200);
    WT_HAS(body(), "\"out_of_scope\":true");
    WT_LACKS(body(), "02:11:22");
    WT_EQ(route("scope=local&x=1", MONO0), 400);
    WT_EQ(route("scope=monitor", MONO0), 200);
    WT_HAS(body(), "02:11:22:33:44:55");
}

/* The feed: sloth-wifi's stream reaches the table, sloth-rf's never
 * does. Seen red (the row held) with web_df_record() called in
 * split_line()'s WEB_FEED_RF branch. */
static void test_webdf_feed(void) {
    fresh();
    web_live_t *live = calloc(1, sizeof(*live));
    web_feed_t *f = calloc(1, sizeof(*f));
    WT_ASSERT(live && f);
    if (!live || !f) { free(live); free(f); return; }
    web_live_init(live, NULL);
    char line[1024];
    f->df = &D;
    f->role = WEB_FEED_RF;
    snprintf(line, sizeof(line), "%s\n", LEAN);
    web_feed_bytes(f, live, line, strlen(line), MONO0);
    WT_EQ(D.records, 0);
    f->role = WEB_FEED_WIFI;
    web_feed_bytes(f, live, line, strlen(line), MONO0);
    WT_EQ(D.records, 1);
    f->role = WEB_FEED_ONLY;
    snprintf(line, sizeof(line), "%s\n", RADIO1);
    web_feed_bytes(f, live, line, strlen(line), MONO0);
    WT_EQ(D.records, 2);
    web_live_destroy(live);
    free(live);
    free(f);
}

/* The page: the module, its containers, its hooks, and its words. */
static void test_webdf_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "window.SlothDf = {");
    WT_HAS(p, "id=\"w-df\"");
    WT_HAS(p, "id=\"w-df-state\"");
    WT_HAS(p, "id=\"w-df-radios\"");
    WT_HAS(p, "id=\"w-df-em\"");
    WT_HAS(p, "if (v === \"wifi\" && window.SlothDf) SlothDf.show();");
    WT_HAS(p, "if (window.SlothDf) SlothDf.init({ getJSON: getJSON, errText: errText, shortStamp: shortStamp });");
    WT_HAS(p, "H.getJSON(\"/api/df\")");
    WT_HAS(p,
        "  function stateText(j) {\n"
        "    if (!j) return \"not known\";\n"
        "    if (j.out_of_scope) return String(j.reason || \"\");\n"
        "    if (j.reported === false)\n"
        "      return \"not reported: this sloth's stream (JSONL \" + (j.jsonl_version || \"before 1.0.0\") +\n"
        "             \") does not carry direction finding; it needs 2.2.0\";\n");
    WT_HAS(p, "      return \"off: sloth has written no radio (it runs without --df-iface, or its next heartbeat, at most 5 min away, has not come yet)\";\n");
    WT_HAS(p, "    if (up < 2) t += \"; fewer than two radios listening, so nothing can be compared\";\n");
    /* The page says what the card is not. */
    WT_HAS(p, "What this is not: a bearing, a side of the line, or a distance; radios with unlike antennas give leans that mean nothing");
    /* textContent only: the module writes no markup. */
    const char *m = strstr(p, "// slothweb: the direction-finding card");
    const char *e = m ? strstr(m, "window.SlothDf = {") : NULL;
    WT_ASSERT(m && e);
    if (m && e) {
        size_t n = (size_t)(e - m);
        char *mod = malloc(n + 1);
        WT_ASSERT(mod != NULL);
        if (mod) {
            memcpy(mod, m, n);
            mod[n] = '\0';
            WT_LACKS(mod, "innerHTML");
            WT_LACKS(mod, "insertAdjacentHTML");
            WT_LACKS(mod, "setAttribute");
            WT_LACKS(mod, "document.write");
            free(mod);
        }
    }
}

void run_webdf_tests(void) {
    WT_RUN(test_webdf_reported);
    WT_RUN(test_webdf_route);
    WT_RUN(test_webdf_refuses);
    WT_RUN(test_webdf_stale_and_bounds);
    WT_RUN(test_webdf_worst_case_fits);
    WT_RUN(test_webdf_scope);
    WT_RUN(test_webdf_feed);
    WT_RUN(test_webdf_page);
    if (inited) { web_df_destroy(&D); inited = 0; }
}
