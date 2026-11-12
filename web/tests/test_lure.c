/* The KARMA and key-harvest evidence (web_lure.h): sloth's
 * `karma_suspect`, `harvest_station` and `harvest_chain` records in the
 * shape src/jsonl.c writes them (the lines below are the ones
 * tests/test_jsonl_lures.c asserts sloth writes), kept by slothweb,
 * answered on /api/lures, and the page's half pinned out of the served
 * page.
 *
 * Absence assertions, each seen red under the mutation named beside it
 * and restored. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "web_jsonl.h"
#include "web_lure.h"
#include "web_routes.h"
#include "web_scope.h"
#include "wtest.h"

static web_lure_t L;
static web_jrec_t R;
static int inited;
static char g_out[131072];

#define MONO0 900000LL
#define T     1800000000LL

static void feed_at(const char *line, long long ms) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_lure_record(&L, &R, ms);
}
static void feed(const char *line) { feed_at(line, MONO0); }

static void fresh(void) {
    if (inited) web_lure_destroy(&L);
    WT_EQ(web_lure_init(&L), 0);
    inited = 1;
}

static int route(const char *query, long long now_ms) {
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.lure = &L;
    h.wall_s = T + 5;
    h.now_ms = now_ms;
    web_req_t *rq = calloc(1, sizeof(*rq));
    web_resp_t r;
    if (!rq) return -1;
    snprintf(rq->path, sizeof(rq->path), "/api/lures");
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

static const char KARMA[] =
    "{\"type\":\"karma_suspect\",\"ts\":1800000000,\"bssid\":\"02:11:22:33:44:55\","
    "\"state\":\"live\",\"ssids\":1,\"ie_postures\":1,\"ie_collapsed\":0,\"forged\":3,"
    "\"forge_stations\":2,\"pnl_best\":2,\"lure_chain\":1,\"score\":4,"
    "\"top_ssid\":\"Cafe <b>\\\"Free\\\"\\u0001\",\"tool\":\"airbase-ng\",\"last_seen\":1799999990}";
static const char STA[] =
    "{\"type\":\"harvest_station\",\"ts\":1800000000,\"sta\":\"02:aa:00:00:00:01\","
    "\"state\":\"live\",\"asked\":5,\"m1_bssids\":4,\"unanswered\":4,\"unanswered_kde\":3,"
    "\"answered\":0,\"dropped\":0,\"first_seen\":1799999000,\"last_seen\":1799999900}";
static const char CHAIN[] =
    "{\"type\":\"harvest_chain\",\"ts\":1800000000,\"bssid\":\"0a:bb:00:00:00:09\","
    "\"state\":\"live\",\"victims\":2,\"disconnects\":6,\"dropped\":0,"
    "\"first_seen\":1799999500,\"last_seen\":1799999800}";
static const char HEALTH13[] = "{\"type\":\"sensor_health\",\"ts\":1800000000,\"jsonl_version\":\"1.3.0\"}";

/* Before anything: "not known", never "none". With a 1.2.0 stream:
 * "does not report". Seen red with web_lure_reported() answering 0
 * before any sensor_health. */
static void test_lure_reported(void) {
    fresh();
    WT_EQ(web_lure_reported(&L), -1);
    WT_EQ(web_lure_reported(NULL), -1);
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"reported\":null,\"jsonl_version\":null,\"karma\":[],\"stations\":[],\"chains\":[]");
    feed("{\"type\":\"sensor_health\",\"ts\":1,\"jsonl_version\":\"1.2.0\"}");
    WT_EQ(web_lure_reported(&L), 0);
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"reported\":false,\"jsonl_version\":\"1.2.0\"");
    feed("{\"type\":\"sensor_health\",\"ts\":1}");            /* before 1.0.0 */
    WT_EQ(web_lure_reported(&L), 0);
    feed("{\"type\":\"sensor_health\",\"ts\":1,\"jsonl_version\":\"one\"}");   /* ignored */
    WT_EQ(web_lure_reported(&L), 0);
    feed(HEALTH13);
    WT_EQ(web_lure_reported(&L), 1);
    feed("{\"type\":\"sensor_health\",\"ts\":1,\"jsonl_version\":\"2.0.0\"}");
    WT_EQ(web_lure_reported(&L), 1);
    feed("{\"type\":\"sensor_health\",\"ts\":1,\"jsonl_version\":\"1.10.0\"}");
    WT_EQ(web_lure_reported(&L), 1);
}

/* The three rows on the route, every member, the SSID through the JSON
 * writer (markup inert, the control byte escaped). */
static void test_lure_route(void) {
    fresh();
    feed(HEALTH13);
    feed(KARMA);
    feed(STA);
    feed(CHAIN);
    WT_EQ(L.records, 3);
    WT_EQ(L.rejected, 0);
    WT_EQ(route("", MONO0 + 4000), 200);
    const char *b = body();
    WT_HAS(b, "{\"now\":1800000005,\"reported\":true,\"jsonl_version\":\"1.3.0\",\"karma\":["
              "{\"bssid\":\"02:11:22:33:44:55\",\"ts\":1800000000,\"age_s\":4,\"ssids\":1,"
              "\"ie_postures\":1,\"ie_collapsed\":false,\"forged\":3,\"forge_stations\":2,"
              "\"pnl_best\":2,\"lure_chain\":true,\"score\":4,\"top_ssid\":\"Cafe ");
    WT_LACKS(b, "<b>");
    WT_LACKS(b, "\x01");
    WT_HAS(b, "\"tool\":\"airbase-ng\",\"last_seen\":1799999990}]");
    WT_HAS(b, "\"stations\":[{\"sta\":\"02:aa:00:00:00:01\",\"ts\":1800000000,\"age_s\":4,"
              "\"asked\":5,\"m1_bssids\":4,\"unanswered\":4,\"unanswered_kde\":3,\"answered\":0,"
              "\"dropped\":0,\"first_seen\":1799999000,\"last_seen\":1799999900}]");
    WT_HAS(b, "\"chains\":[{\"bssid\":\"0a:bb:00:00:00:09\",\"ts\":1800000000,\"age_s\":4,"
              "\"victims\":2,\"disconnects\":6,\"dropped\":0,\"first_seen\":1799999500,"
              "\"last_seen\":1799999800}]");
    WT_HAS(b, "\"stale\":0,\"records\":3,\"rejected\":0,\"overflow\":0}");
    /* No parameters. */
    WT_EQ(route("limit=3", MONO0), 400);
    WT_HAS(body(), "unknown_parameter");
    /* No tables bound. */
    size_t len = 0;
    int st = 0;
    WT_EQ(web_lure_route(NULL, "", T, MONO0, 0, g_out, sizeof(g_out), &len, &st), 0);
    WT_EQ(st, 503);
}

/* A newer record replaces its key's row; gone removes it at once. Seen
 * red (the row still listed) with the gone branch returning before the
 * memset. */
static void test_lure_replace_and_gone(void) {
    fresh();
    feed(HEALTH13);
    feed(KARMA);
    feed("{\"type\":\"karma_suspect\",\"ts\":1800000030,\"bssid\":\"02:11:22:33:44:55\","
         "\"state\":\"live\",\"ssids\":1,\"ie_postures\":1,\"ie_collapsed\":0,\"forged\":5,"
         "\"forge_stations\":3,\"pnl_best\":2,\"lure_chain\":0,\"score\":4,"
         "\"top_ssid\":\"Cafe\",\"tool\":\"\",\"last_seen\":1800000020}");
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"forged\":5,\"forge_stations\":3");
    WT_LACKS(body(), "\"forged\":3");
    feed("{\"type\":\"karma_suspect\",\"ts\":1800000060,\"bssid\":\"02:11:22:33:44:55\",\"state\":\"gone\"}");
    WT_EQ(L.gone, 1);
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"karma\":[]");
    /* A gone for a key never held changes nothing. */
    feed("{\"type\":\"harvest_chain\",\"ts\":1800000060,\"bssid\":\"0a:bb:00:00:00:09\",\"state\":\"gone\"}");
    WT_EQ(L.gone, 1);
    WT_EQ(L.rejected, 0);
}

/* Malformed records are refused whole: a missing or out-of-range
 * member, a bad MAC, a bad state, an SSID past 32 code points. Seen red
 * (the long SSID kept) with jtext()'s code-point bound removed. */
static void test_lure_refuses(void) {
    fresh();
    static const char *const BAD[] = {
        "{\"type\":\"harvest_chain\",\"ts\":1800000000,\"bssid\":\"0a:bb:00:00:00:09\","
        "\"state\":\"live\",\"victims\":2,\"dropped\":0,\"first_seen\":1,\"last_seen\":1}",
        "{\"type\":\"harvest_chain\",\"ts\":1800000000,\"bssid\":\"0a:bb:00:00:00:09\","
        "\"state\":\"live\",\"victims\":-1,\"disconnects\":6,\"dropped\":0,\"first_seen\":1,\"last_seen\":1}",
        "{\"type\":\"harvest_chain\",\"ts\":1800000000,\"bssid\":\"0a:bb:00:00:00\","
        "\"state\":\"live\",\"victims\":2,\"disconnects\":6,\"dropped\":0,\"first_seen\":1,\"last_seen\":1}",
        "{\"type\":\"harvest_chain\",\"ts\":1800000000,\"bssid\":\"0a:bb:00:00:00:09\","
        "\"state\":\"maybe\",\"victims\":2,\"disconnects\":6,\"dropped\":0,\"first_seen\":1,\"last_seen\":1}",
        "{\"type\":\"harvest_station\",\"ts\":1800000000,\"bssid\":\"02:aa:00:00:00:01\","
        "\"state\":\"live\",\"asked\":5,\"m1_bssids\":4,\"unanswered\":4,\"unanswered_kde\":3,"
        "\"answered\":0,\"dropped\":0,\"first_seen\":1,\"last_seen\":1}",
        "{\"type\":\"karma_suspect\",\"ts\":1800000000,\"bssid\":\"02:11:22:33:44:55\","
        "\"state\":\"live\",\"ssids\":1,\"ie_postures\":1,\"ie_collapsed\":2,\"forged\":3,"
        "\"forge_stations\":2,\"pnl_best\":2,\"lure_chain\":1,\"score\":4,"
        "\"top_ssid\":\"x\",\"tool\":\"\",\"last_seen\":1}",
        "{\"type\":\"karma_suspect\",\"ts\":1800000000,\"bssid\":\"02:11:22:33:44:55\","
        "\"state\":\"live\",\"ssids\":1,\"ie_postures\":1,\"ie_collapsed\":0,\"forged\":3,"
        "\"forge_stations\":2,\"pnl_best\":2,\"lure_chain\":1,\"score\":4,"
        "\"top_ssid\":\"0123456789012345678901234567890123\",\"tool\":\"\",\"last_seen\":1}",
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) feed(BAD[i]);
    WT_EQ(L.rejected, sizeof(BAD) / sizeof(BAD[0]));
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"karma\":[],\"stations\":[],\"chains\":[]");
    /* 32 code points of three octets each is an SSID sloth can write. */
    char ok[1024];
    char ss[200] = "";
    for (int i = 0; i < 32; i++) strcat(ss, "\\ufffd");
    snprintf(ok, sizeof(ok),
             "{\"type\":\"karma_suspect\",\"ts\":1800000000,\"bssid\":\"02:11:22:33:44:55\","
             "\"state\":\"live\",\"ssids\":1,\"ie_postures\":1,\"ie_collapsed\":0,\"forged\":3,"
             "\"forge_stations\":2,\"pnl_best\":2,\"lure_chain\":1,\"score\":4,"
             "\"top_ssid\":\"%s\",\"tool\":\"\",\"last_seen\":1}", ss);
    feed(ok);
    WT_EQ(L.rejected, sizeof(BAD) / sizeof(BAD[0]));
}

/* A row not refreshed for WEB_LURE_STALE_MS is left out and counted;
 * a full table refuses a new key, unless a stale row gives its slot. */
static void test_lure_stale_and_bounds(void) {
    fresh();
    char line[512];
    for (int i = 0; i < WEB_LURE_CHAIN; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"harvest_chain\",\"ts\":1800000000,\"bssid\":\"0a:bb:00:00:00:%02x\","
                 "\"state\":\"live\",\"victims\":1,\"disconnects\":2,\"dropped\":0,"
                 "\"first_seen\":1,\"last_seen\":1}", i);
        feed_at(line, MONO0 + i);
    }
    feed_at("{\"type\":\"harvest_chain\",\"ts\":1800000000,\"bssid\":\"0a:bb:00:00:01:00\","
            "\"state\":\"live\",\"victims\":1,\"disconnects\":2,\"dropped\":0,"
            "\"first_seen\":1,\"last_seen\":1}", MONO0 + 100);
    WT_EQ(L.overflow, 1);
    /* Past the stale bound: every row left out, and a new key takes a
     * stale slot. */
    long long later = MONO0 + WEB_LURE_STALE_MS + 1000;
    WT_EQ(route("", later), 200);
    WT_HAS(body(), "\"chains\":[],\"stale\":16");
    feed_at("{\"type\":\"harvest_chain\",\"ts\":1800000700,\"bssid\":\"0a:bb:00:00:01:00\","
            "\"state\":\"live\",\"victims\":1,\"disconnects\":2,\"dropped\":0,"
            "\"first_seen\":1,\"last_seen\":1}", later);
    WT_EQ(L.overflow, 1);
    WT_EQ(route("", later), 200);
    WT_HAS(body(), "\"bssid\":\"0a:bb:00:00:01:00\"");
    WT_HAS(body(), "\"stale\":15");
}

/* The worst-case answer fits: every table full, every string at its
 * bound and every octet one the writer expands. */
static void test_lure_worst_case_fits(void) {
    fresh();
    feed(HEALTH13);
    char ssid[256] = "", tool[400] = "", line[2048];
    for (int i = 0; i < 32; i++) strcat(ssid, "\\u0001");
    for (int i = 0; i < WEB_LURE_TOOL_MAX; i++) strcat(tool, "<");
    for (int i = 0; i < WEB_LURE_KARMA; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"karma_suspect\",\"ts\":1800000000,\"bssid\":\"02:11:22:33:%02x:55\","
                 "\"state\":\"live\",\"ssids\":1000000,\"ie_postures\":1000000,\"ie_collapsed\":1,"
                 "\"forged\":1000000,\"forge_stations\":1000000,\"pnl_best\":1000000,\"lure_chain\":1,"
                 "\"score\":1000000,\"top_ssid\":\"%s\",\"tool\":\"%s\",\"last_seen\":1099511627776}",
                 i, ssid, tool);
        feed(line);
    }
    for (int i = 0; i < WEB_LURE_STA; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"harvest_station\",\"ts\":1099511627776,\"sta\":\"02:aa:00:00:00:%02x\","
                 "\"state\":\"live\",\"asked\":1000000,\"m1_bssids\":1000000,\"unanswered\":1000000,"
                 "\"unanswered_kde\":1000000,\"answered\":1000000,\"dropped\":1000000,"
                 "\"first_seen\":1099511627776,\"last_seen\":1099511627776}", i);
        feed(line);
    }
    for (int i = 0; i < WEB_LURE_CHAIN; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"harvest_chain\",\"ts\":1099511627776,\"bssid\":\"0a:bb:00:00:00:%02x\","
                 "\"state\":\"live\",\"victims\":1000000,\"disconnects\":1000000,\"dropped\":1000000,"
                 "\"first_seen\":1099511627776,\"last_seen\":1099511627776}", i);
        feed(line);
    }
    WT_EQ(L.rejected, 0);
    WT_EQ(L.overflow, 0);
    /* The space an answer has behind its header (web_routes.h). */
    static char out[65536 - WEB_LIVE_HDR_RESERVE];
    size_t len = 0;
    int st = 0;
    WT_EQ(web_lure_route(&L, "", T, MONO0, 0, out, sizeof(out), &len, &st), 0);
    WT_EQ(st, 200);
    WT_ASSERT(len > 40000);
}

/* Local: the query is still checked, then the one out_of_scope answer. */
static void test_lure_scope(void) {
    fresh();
    feed(KARMA);
    WT_EQ(route("scope=local", MONO0), 200);
    WT_HAS(body(), "\"out_of_scope\":true");
    WT_LACKS(body(), "02:11:22");
    WT_EQ(route("scope=local&x=1", MONO0), 400);
    WT_EQ(route("scope=monitor", MONO0), 200);
    WT_HAS(body(), "02:11:22:33:44:55");
}

/* The page: the module, its containers, its hook, and its words. */
static void test_lure_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "window.SlothLure = {");
    WT_HAS(p, "id=\"w-lure\"");
    WT_HAS(p, "id=\"w-lure-karma\"");
    WT_HAS(p, "id=\"w-lure-sta\"");
    WT_HAS(p, "id=\"w-lure-chain\"");
    WT_HAS(p, "if (v === \"wifi\" && window.SlothLure) SlothLure.show();");
    WT_HAS(p, "if (window.SlothLure) SlothLure.init({ getJSON: getJSON, errText: errText, shortStamp: shortStamp });");
    WT_HAS(p,
        "  function stateText(j) {\n"
        "    if (!j) return \"not known\";\n"
        "    if (j.out_of_scope) return String(j.reason || \"\");\n"
        "    if (j.reported === false)\n"
        "      return \"not reported: this sloth's stream (JSONL \" + (j.jsonl_version || \"before 1.0.0\") +\n"
        "             \") does not carry KARMA or key-harvest evidence; it needs 1.3.0\";\n"
        "    if (j.reported === null)\n"
        "      return \"not known: sloth has not reported its stream version on this connection yet\";\n");
    WT_HAS(p, "    var t = k + s + c === 0 ? \"none: sloth's KARMA and key-harvest tables are empty\"\n");
    /* textContent only: the module writes no markup. */
    const char *m = strstr(p, "// slothweb: the KARMA and key-harvest card");
    const char *e = m ? strstr(m, "window.SlothLure = {") : NULL;
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

void run_lure_tests(void) {
    WT_RUN(test_lure_reported);
    WT_RUN(test_lure_route);
    WT_RUN(test_lure_replace_and_gone);
    WT_RUN(test_lure_refuses);
    WT_RUN(test_lure_stale_and_bounds);
    WT_RUN(test_lure_worst_case_fits);
    WT_RUN(test_lure_scope);
    WT_RUN(test_lure_page);
    if (inited) { web_lure_destroy(&L); inited = 0; }
}
